// spor's self-hosted store: SQLite (node:sqlite, built into Node 22.13+), one row per hourly
// bucket of identical data points. The columns are the Analytics Engine schema (host, then the
// eight blobs) plus source and the count n, so rows() answers with exactly the row shapes that
// queries() gets from AE, and build(), render() and toJSON() run unchanged.
//
// Sources never overlap for a host. AE rows ("ae") are replaced window by window on each sync.
// Local rows ("nginx", "ingest") are added. A host in config.local gets a cutover the first time a
// local point arrives for it: the next full hour (or this one, if AE has nothing for the host).
// Before it the host comes from AE, from it on locally.
import { DatabaseSync } from "node:sqlite"
import { OK_LIMIT, clampDays, validHost, windowStart } from "./report.js"

export const HOUR = 3600
export const FIELDS = ["host", "path", "referer", "ua", "country", "status", "bot", "origin", "method"]

const hourOf = (seconds) => Math.floor(seconds / HOUR) * HOUR

export function openStore(file = ":memory:") {
  const db = new DatabaseSync(file)
  db.exec(`PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS hits (
  hour INTEGER NOT NULL, ${FIELDS.map((f) => `${f} TEXT NOT NULL`).join(", ")}, source TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (hour, ${FIELDS.join(", ")}, source)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`)

  const upsert = db.prepare(`INSERT INTO hits (hour, ${FIELDS.join(", ")}, source, n) VALUES (?, ${FIELDS.map(() => "?").join(", ")}, ?, ?)
ON CONFLICT DO UPDATE SET n = n + excluded.n`)
  const getMeta = db.prepare("SELECT value FROM meta WHERE key = ?")
  const setMeta = db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT DO UPDATE SET value = excluded.value")
  const deleteAE = db.prepare("DELETE FROM hits WHERE source = 'ae' AND hour >= ? AND hour < ?")
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
          if (since !== null && r.hour >= since) continue
          if (r.hour < from || r.hour >= to) continue
          insert(r.hour, r, "ae", Number(r.n) || 0)
        }
      })
    },

    // the five result sets, shaped like queries() over AE: same filters, same LIMITs
    rows(days, host, config, now = Date.now()) {
      const from = Date.parse(windowStart(clampDays(String(days)), now).replace(" ", "T") + "Z") / 1000
      const h = validHost(host, config)
      const where = `FROM hits WHERE hour >= ?${h ? " AND host = ?" : ""}`
      const args = h ? [from, h] : [from]
      const n = "SUM(n) AS n"
      const all = (sql) => db.prepare(sql).all(...args)
      return {
        totals: all(`SELECT host, status, ${n} ${where} GROUP BY host, status`),
        daily: all(`SELECT strftime('%Y-%m-%d', hour, 'unixepoch') AS day, host, ${n} ${where} GROUP BY day, host ORDER BY day`),
        ok: all(`SELECT host, path, referer, ua, country, bot, method, ${n} ${where} AND status >= '200' AND status < '300' AND ua != '' GROUP BY host, path, referer, ua, country, bot, method ORDER BY n DESC, host, path, referer, ua, country, bot, method LIMIT ${OK_LIMIT}`),
        paths: all(`SELECT host, path, status, ${n} ${where} GROUP BY host, path, status ORDER BY n DESC, host, path, status LIMIT 500`),
        origins: all(`SELECT host, origin, ${n} ${where} AND origin != '' GROUP BY host, origin ORDER BY n DESC, host, origin LIMIT 50`)
      }
    },

    close: () => db.close()
  }
}
