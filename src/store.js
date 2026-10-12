// spor's self-hosted store: SQLite (node:sqlite, built into Node 22.13+), one row per hourly
// bucket of identical data points. The columns are the Analytics Engine schema (host, then the
// fourteen blobs) plus source and the count n, so rows() answers with exactly the row shapes that
// queries() gets from AE, and build(), render() and toJSON() run unchanged.
//
// Sources never overlap for a host. AE rows ("ae") are replaced window by window on each sync.
// Local rows ("nginx", "ingest") are added. A host in config.local gets a cutover the first time a
// local point arrives for it: the next full hour (or this one, if AE has nothing for the host).
// Before it the host comes from AE, from it on locally.
import { DatabaseSync } from "node:sqlite"
import { OK_LIMIT, LIMITS, clampDays, validHost, hostSql, parseFilters, span, filterSql, classSql } from "./report.js"

export const HOUR = 3600
// the Analytics Engine blobs in order (AE_COLUMNS in src/report.js), host first
export const FIELDS = ["host", "path", "referer", "ua", "country", "status", "bot", "origin", "method", "city", "region", "asn", "asorg", "visitor", "ip", "lat", "lon", "sink", "sinkctx"]
// the store's column for each filter and class field: the same names
const COLS = Object.fromEntries(FIELDS.map((f) => [f, f]))
const createHits = (name) => `CREATE TABLE IF NOT EXISTS ${name} (
  hour INTEGER NOT NULL, ${FIELDS.map((f) => `${f} TEXT NOT NULL DEFAULT ''`).join(", ")}, source TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (hour, ${FIELDS.join(", ")}, source)
) WITHOUT ROWID`

const hourOf = (seconds) => Math.floor(seconds / HOUR) * HOUR

export function openStore(file = ":memory:") {
  const db = new DatabaseSync(file)
  db.exec("PRAGMA journal_mode = WAL")
  const columns = db.prepare("SELECT name FROM pragma_table_info('hits')").all().map((r) => r.name)
  const kept = FIELDS.filter((f) => columns.includes(f))
  if (columns.length && kept.length < FIELDS.length) {
    // a store from before some of these columns: the key spans every column, so rebuild the table
    // and carry the rows over with the new columns empty
    db.exec(`BEGIN; ALTER TABLE hits RENAME TO hits_old; ${createHits("hits")};
INSERT INTO hits (hour, ${kept.join(", ")}, source, n) SELECT hour, ${kept.join(", ")}, source, n FROM hits_old;
DROP TABLE hits_old; COMMIT`)
  }
  db.exec(`${createHits("hits")};
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`)

  const upsert = db.prepare(`INSERT INTO hits (hour, ${FIELDS.join(", ")}, source, n) VALUES (?, ${FIELDS.map(() => "?").join(", ")}, ?, ?)
ON CONFLICT DO UPDATE SET n = n + excluded.n`)
  const getMeta = db.prepare("SELECT value FROM meta WHERE key = ?")
  const setMeta = db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT DO UPDATE SET value = excluded.value")
  // source "ae" is AE's traffic; "sink" is AE's bait for a local host after its cutover, which
  // nginx counted as traffic already: only the sinkhole view reads it
  const deleteAE = db.prepare("DELETE FROM hits WHERE source IN ('ae', 'sink') AND hour >= ? AND hour < ?")
  const hasAE = db.prepare("SELECT 1 AS yes FROM hits WHERE source = 'ae' AND host = ? LIMIT 1")

  const meta = (key) => getMeta.get(key)?.value ?? null
  const cutover = (host) => {
    const value = meta(`cutover:${host}`)
    return value === null ? null : Number(value)
  }
  const transaction = (fn) => {
    db.exec("BEGIN")
    try {
      fn()
      db.exec("COMMIT")
    } catch (error) {
      db.exec("ROLLBACK")
      throw error
    }
  }
  const insert = (hour, point, source, n) => upsert.run(hour, ...FIELDS.map((f) => String(point[f] ?? "")), source, n)

  return {
    db,
    meta,
    setMeta: (key, value) => setMeta.run(key, String(value)),
    cutover,

    // one local data point (nginx or ingest), at unix time `seconds`. Points before the host's
    // cutover are dropped: AE still owns that hour. Returns whether the point was stored.
    addLocal(point, source, seconds = Date.now() / 1000) {
      let since = cutover(point.host)
      if (since === null) {
        // AE owns the current hour of a host it has data for; a host it never saw starts now
        since = hourOf(seconds) + (hasAE.get(point.host) ? HOUR : 0)
        setMeta.run(`cutover:${point.host}`, String(since))
      }
      if (seconds < since) return false
      insert(hourOf(seconds), point, source, 1)
      return true
    },

    // replace the AE rows in [from, to) with `rows` ({ hour, n, ...FIELDS }), skipping hours a
    // local source owns
    replaceAE(from, to, rows) {
      transaction(() => {
        deleteAE.run(from, to)
        for (const r of rows) {
          const since = cutover(r.host)
          if (r.hour < from || r.hour >= to) continue
          if (since !== null && r.hour >= since) {
            // after a local host's cutover nginx counts its traffic. Canary uses and challenges
            // stay (the tap answered them; nginx never saw them); bait nginx did see, as the origin's
            // answer, so it is kept apart for the sinkhole view only
            if (/^(use:|challenge$)/.test(r.sink || "")) insert(r.hour, r, "ae", Number(r.n) || 0)
            else if (/^bait:/.test(r.sink || "")) insert(r.hour, r, "sink", Number(r.n) || 0)
            continue
          }
          insert(r.hour, r, "ae", Number(r.n) || 0)
        }
      })
    },

    // the result sets of queries() in src/report.js, over the store: same filters, same LIMITs,
    // same tie-breaks. Filter values are bound parameters here.
    rows(days, host, config, now = Date.now(), filters = {}) {
      const f = parseFilters(new URLSearchParams(Object.entries(filters).filter(([, v]) => typeof v === "string")), now)
      const w = span(clampDays(String(days)), f, now)
      const h = validHost(host, config)
      const values = [w.fromSeconds, w.toSeconds]
      const bind = (v) => {
        values.push(v)
        return "?"
      }
      // bait kept apart from traffic (source "sink") counts in the sinkhole view only
      const where = `FROM hits WHERE hour >= ? AND hour < ?${f.view === "sink" ? "" : " AND source != 'sink'"}${hostSql(h, config, "host", bind)}${filterSql(f, COLS, (v) => {
        values.push(v)
        return "?"
      })}`
      // the map's places skip the country and city filters (their own bound values)
      const { country, city, ...rest } = f
      // the selected places sort first (sel), so the LIMIT never drops them; its values come first
      const selSql = country ? `CASE WHEN country = ?${city ? " AND city = ?" : ""} THEN 1 ELSE 0 END` : "0"
      const placeValues = [...(country ? [country] : []), ...(country && city ? [city] : []), w.fromSeconds, w.toSeconds]
      const placeBind = (v) => {
        placeValues.push(v)
        return "?"
      }
      const wherePlaces = `FROM hits WHERE hour >= ? AND hour < ?${rest.view === "sink" ? "" : " AND source != 'sink'"}${hostSql(h, config, "host", placeBind)}${filterSql(rest, COLS, placeBind)}`
      const n = "SUM(n) AS n"
      const ok = "status >= '200' AND status < '300'"
      const people = f.class || f.view === "sink" ? "" : ` AND ${classSql("human", COLS)}`
      const human = classSql("human", COLS)
      const bucket = w.step * 3600
      const all = (sql) => db.prepare(sql).all(...values)
      return {
        totals: all(`SELECT host, status, ${n} ${where} GROUP BY host, status`),
        daily: all(`SELECT strftime('%Y-%m-%d %H:00:00', (hour / ${bucket}) * ${bucket}, 'unixepoch') AS day, host, ${n} ${where} GROUP BY day, host ORDER BY day`),
        ok: all(`SELECT host, path, referer, ua, country, bot, method, asorg, ${n} ${where} AND ${ok} AND ua != '' GROUP BY host, path, referer, ua, country, bot, method, asorg ORDER BY n DESC, host, path, referer, ua, country, bot, method, asorg LIMIT ${OK_LIMIT}`),
        paths: all(`SELECT host, path, status, ${n} ${where} GROUP BY host, path, status ORDER BY n DESC, host, path, status LIMIT 500`),
        origins: all(`SELECT host, origin, ${n} ${where} AND origin != '' GROUP BY host, origin ORDER BY n DESC, host, origin LIMIT 50`),
        geo: all(`SELECT host, country, region, city, lat, lon, ${n} ${where} AND ${ok} AND city != ''${people} GROUP BY host, country, region, city, lat, lon ORDER BY n DESC, host, country, region, city, lat, lon LIMIT ${LIMITS.geo}`),
        places: db.prepare(`SELECT host, country, region, city, lat, lon, ${selSql} AS sel, ${n} ${wherePlaces} AND ${ok} AND city != '' AND lat != ''${rest.class || rest.view === "sink" ? "" : ` AND ${human}`} GROUP BY host, country, region, city, lat, lon, sel ORDER BY sel DESC, n DESC, host, country, region, city, lat, lon LIMIT ${LIMITS.geo}`).all(...placeValues),
        networks: all(`SELECT host, asn, asorg, ${n} ${where} AND asn != '' GROUP BY host, asn, asorg ORDER BY n DESC, host, asn, asorg LIMIT ${LIMITS.networks}`),
        agents: all(`SELECT host, ua, bot, asorg, ${n} ${where} AND NOT ${human} GROUP BY host, ua, bot, asorg ORDER BY n DESC, host, ua, bot, asorg LIMIT ${LIMITS.agents}`),
        visitors: all(`SELECT host, strftime('%Y-%m-%d', hour, 'unixepoch') AS day, count(DISTINCT visitor) AS v ${where} AND visitor != ''${people} GROUP BY host, day`),
        ips: all(`SELECT host, ip, asorg, country, ${n} ${where} AND ip != '' GROUP BY host, ip, asorg, country ORDER BY n DESC, host, ip, asorg, country LIMIT ${LIMITS.ips}`),
        ...(f.view === "sink"
          ? {
            sinkkinds: all(`SELECT sink AS kind, host, ${n} ${where} GROUP BY kind, host ORDER BY n DESC, kind, host LIMIT 200`),
            sinkuse: all(`SELECT strftime('%Y-%m-%d %H:00:00', hour, 'unixepoch') AS at, host, path, sink AS kind, sinkctx AS ctx, ip, asorg, country, ua, method, ${n} ${where} AND sink LIKE 'use:%' GROUP BY at, host, path, kind, ctx, ip, asorg, country, ua, method ORDER BY at DESC, host, path, kind, ctx, ip, asorg, country, ua, method LIMIT ${LIMITS.canaries}`)
          }
          : {}),
        // traffic only: bait kept apart (source "sink") is no request of its own
        hosts: db.prepare(`SELECT host, ${n} FROM hits WHERE hour >= ? AND hour < ? AND source != 'sink' GROUP BY host ORDER BY n DESC, host LIMIT 200`).all(w.fromSeconds, w.toSeconds),
        // AE's toDayOfWeek numbering: 1 = Monday ... 7 = Sunday (SQLite's %w is 0 = Sunday)
        heat: all(`SELECT ((CAST(strftime('%w', hour, 'unixepoch') AS INTEGER) + 6) % 7) + 1 AS dow, CAST(strftime('%H', hour, 'unixepoch') AS INTEGER) AS hr, ${n} ${where} GROUP BY dow, hr`)
      }
    },

    close: () => db.close()
  }
}
