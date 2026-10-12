// spor's IP lookup for the self-hosted backend: ASN and network name from IPtoASN (public domain),
// and country, region and city from DB-IP Lite (CC BY 4.0, so the dashboard credits it). `spor geo
// update` loads both into their own SQLite file, written beside the old one and renamed over it;
// the server opens it at start, so restart the server after an update. A lookup is one indexed
// range query per table. City data is approximate: trust the country, then the region.
import { DatabaseSync } from "node:sqlite"
import { createGunzip } from "node:zlib"
import { createInterface } from "node:readline"
import { Readable } from "node:stream"
import { existsSync, renameSync, rmSync } from "node:fs"
import { ipToHex } from "./report.js"

export { ipToHex }

export const ASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
export const cityUrl = (month) => `https://download.db-ip.com/free/dbip-city-lite-${month}.csv.gz`
export const CREDIT = `<a href="https://db-ip.com">IP Geolocation by DB-IP</a>`

// One CSV line, with "quoted, fields" and "" escapes (DB-IP quotes city names)
export function csvFields(line) {
  const out = []
  let field = ""
  let quoted = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quoted) {
      if (c === "\"" && line[i + 1] === "\"") field += line[++i]
      else if (c === "\"") quoted = false
      else field += c
    } else if (c === "\"") quoted = true
    else if (c === ",") {
      out.push(field)
      field = ""
    } else field += c
  }
  out.push(field)
  return out
}

// null when the file is missing: the server then runs without lookups
export function openGeo(file) {
  if (!file || !existsSync(file)) return null
  const db = new DatabaseSync(file)
  const asn = db.prepare("SELECT end, asn, asorg, country FROM asn WHERE start <= ? ORDER BY start DESC LIMIT 1")
  const city = db.prepare("SELECT end, country, region, city FROM city WHERE start <= ? ORDER BY start DESC LIMIT 1")
  return {
    // ip -> { asn, asorg, country, region, city }, each "" when unknown
    lookup(ip) {
      const out = { asn: "", asorg: "", country: "", region: "", city: "" }
      const hex = ipToHex(ip)
      if (!hex) return out
      const a = asn.get(hex)
      if (a && a.end >= hex) Object.assign(out, { asn: a.asn, asorg: a.asorg, country: a.country })
      const c = city.get(hex)
      if (c && c.end >= hex) Object.assign(out, { country: c.country || out.country, region: c.region, city: c.city })
      return out
    },
    close: () => db.close()
  }
}

async function* gzipLines(url, fetchImpl) {
  const res = await fetchImpl(url)
  if (!res.ok) {
    const error = new Error(`${url} answered ${res.status}`)
    error.status = res.status
    throw error
  }
  // pipe() doesn't forward the source's errors: hand them to gunzip, so the loop below rejects
  const source = Readable.fromWeb(res.body)
  const gunzip = createGunzip()
  source.on("error", (error) => gunzip.destroy(error))
  yield* createInterface({ input: source.pipe(gunzip), crlfDelay: Infinity })
}

// Download both sources into `${file}.tmp`, then rename it over `file`. DB-IP publishes a file per
// month, sometimes a few days late: a 404 falls back to the month before. A download with fewer
// ranges than `min` (in 2026: 580,000 networks, 7.8 million city ranges) is treated as broken and
// leaves the old file in place.
export const MIN_RANGES = { asn: 100000, city: 1000000 }
export async function updateGeo(file, { fetchImpl = fetch, now = Date.now(), min = MIN_RANGES } = {}) {
  const tmp = `${file}.tmp`
  rmSync(tmp, { force: true })
  const db = new DatabaseSync(tmp)
  db.exec(`CREATE TABLE asn (start TEXT PRIMARY KEY, end TEXT NOT NULL, asn TEXT NOT NULL, asorg TEXT NOT NULL, country TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE city (start TEXT PRIMARY KEY, end TEXT NOT NULL, country TEXT NOT NULL, region TEXT NOT NULL, city TEXT NOT NULL) WITHOUT ROWID;`)
  const counts = { asn: 0, city: 0, month: "" }
  try {
    db.exec("BEGIN")
    const addAsn = db.prepare("INSERT OR REPLACE INTO asn VALUES (?, ?, ?, ?, ?)")
    for await (const line of gzipLines(ASN_URL, fetchImpl)) {
      const [start, end, asn, country, name] = line.split("\t")
      const s = ipToHex(start)
      const e = ipToHex(end)
      // AS 0 marks unrouted space
      if (!s || !e || !/^\d+$/.test(asn) || asn === "0") continue
      addAsn.run(s, e, asn, String(name || "").slice(0, 64), country === "None" ? "" : String(country || "").slice(0, 2))
      counts.asn++
    }
    const addCity = db.prepare("INSERT OR REPLACE INTO city VALUES (?, ?, ?, ?, ?)")
    for (const back of [0, 1]) {
      const d = new Date(now)
      const month = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - back, 1)).toISOString().slice(0, 7)
      try {
        for await (const line of gzipLines(cityUrl(month), fetchImpl)) {
          const [start, end, , country, region, city] = csvFields(line)
          const s = ipToHex(start)
          const e = ipToHex(end)
          if (!s || !e || country === "ZZ") continue
          addCity.run(s, e, country.slice(0, 2), String(region || "").slice(0, 64), String(city || "").slice(0, 64))
          counts.city++
        }
        counts.month = month
        break
      } catch (error) {
        if (error.status !== 404 || back) throw error
      }
    }
    if (counts.asn < min.asn || counts.city < min.city) throw new Error(`only ${counts.asn} network and ${counts.city} city ranges; keeping the old geo file`)
    db.exec("COMMIT")
  } catch (error) {
    db.exec("ROLLBACK")
    db.close()
    rmSync(tmp, { force: true })
    throw error
  }
  db.close()
  renameSync(tmp, file)
  return counts
}
