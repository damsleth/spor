// spor's self-hosted backend: one Node process (built-ins only) with a SQLite store, serving the
// same dashboard and API as the Worker (src/http.js). It is fed by:
//   - nginx, which sends one JSON access-log line per request over syslog (UDP, loopback);
//     see selfhost/nginx-spor-log.conf. Only hosts in config.local are kept.
//   - POST /api/ingest, Bearer INGEST_TOKEN, a data point in the Analytics Engine shape that the
//     tap writes ({ indexes: [host], blobs: [...14] }), or an array of up to 100 of them.
//   - Analytics Engine (when CF_ACCOUNT_ID and CF_ANALYTICS_TOKEN are set): a backfill of everything
//     AE still holds, then the last few hours re-pulled every SPOR_AE_SYNC_MINUTES.
// Local points get their network, and any missing country, region and city, from the geo file
// (src/geo.js, SPOR_GEO_DB) when it exists. The client IP is kept only with vars.SPOR.recordIp.
// Started by `spor serve`. Put it behind a reverse proxy or `tailscale serve`; it speaks plain HTTP.
import { createServer } from "node:http"
import { createSocket } from "node:dgram"
import { createHash, randomBytes } from "node:crypto"
import { Readable } from "node:stream"
import { dirname, join } from "node:path"
import { requireConfig, safeEqual, AE_COLUMNS } from "./report.js"
import { handle, text } from "./http.js"
import { openStore, HOUR, FIELDS } from "./store.js"
import { openGeo, CREDIT } from "./geo.js"

const DAY = 86400
export const AE_RETENTION_DAYS = 92
export const AE_LIMIT = 10000
export const INGEST_MAX_BYTES = 65536
export const INGEST_MAX_POINTS = 100

function originOf(value) {
  if (!value) return ""
  try {
    return new URL(value).origin
  } catch {
    return ""
  }
}

// every value is attacker-written: strings only, capped like the tap caps them
// Control characters are dropped: SQLite's LIKE stops at a NUL, so the classes would disagree.
const COORD = /^-?\d{1,3}(\.\d{1,6})?$/
function clean({ host, path, referer, ua, country, status, bot, origin, method, city, region, asn, asorg, visitor, ip, lat, lon, sink, sinkctx }) {
  // eslint-disable-next-line no-control-regex
  const s = (v, max) => (typeof v === "string" ? v : v === undefined || v === null ? "" : String(v)).replace(/[\x00-\x1f\x7f]/g, "").slice(0, max)
  return {
    host: s(host, 253).toLowerCase().replace(/\.$/, ""), path: s(path, 64), referer: s(referer, 256), ua: s(ua, 256), country: s(country, 8),
    status: s(status, 3), bot: s(bot, 64), origin: s(origin, 256), method: s(method, 16),
    city: s(city, 64), region: s(region, 64), asn: /^\d{1,10}$/.test(s(asn, 10)) ? s(asn, 10) : "", asorg: s(asorg, 64),
    visitor: /^[0-9a-f]{16}$/.test(s(visitor, 16)) ? s(visitor, 16) : "", ip: s(ip, 45).toLowerCase(),
    // coordinates as the tap writes them: text with 2 decimals
    lat: COORD.test(s(lat, 12)) ? Number(lat).toFixed(2) : "", lon: COORD.test(s(lon, 12)) ? Number(lon).toFixed(2) : "",
    // the tap's sinkhole marks: "bait:<kind>", "use:<kind>" or "challenge", and the probe a key came from
    sink: /^((bait|use):[a-z]+|challenge)$/.test(s(sink, 24)) ? s(sink, 24) : "", sinkctx: s(sinkctx, 200)
  }
}

// the tap's Analytics Engine data point -> store fields
export function fromDataPoint(point) {
  if (!point || !Array.isArray(point.indexes) || !Array.isArray(point.blobs)) return null
  const [path, referer, ua, country, status, bot, origin, method, city, region, asn, asorg, visitor, ip, lat, lon, sink, sinkctx] = point.blobs
  return clean({ host: point.indexes[0], path, referer, ua, country, status, bot, origin, method, city, region, asn, asorg, visitor, ip, lat, lon, sink, sinkctx })
}

// A local point (nginx), finished like the tap finishes one: the network, and any country, region or
// city the request didn't carry, from the geo file; a daily visitor hash; the IP only with recordIp.
// The hash is salted per day in memory, as the tap salts it from KV, and unsalted with recordIp.
// The hash input matches the tap's: the user agent cut to 256 characters, the IP lowercased.
// ponytail: a restart draws new salts, so a visitor seen before and after one counts twice that day
const salts = new Map()
function saltFor(day) {
  if (!salts.has(day)) {
    salts.set(day, randomBytes(16).toString("hex"))
    // keep yesterday's too: UDP lines can arrive out of order around midnight
    for (const d of salts.keys()) if (salts.size > 2 && d !== day) salts.delete(d)
  }
  return salts.get(day)
}
export function enrich(point, { geo = null, recordIp = false, now = Date.now() } = {}) {
  const ip = String(point.ip || "").toLowerCase()
  const found = ip && geo ? geo.lookup(ip) : {}
  const day = new Date(now).toISOString().slice(0, 10)
  const ua = String(point.ua || "").slice(0, 256)
  const visitor = ip ? createHash("sha256").update(`${recordIp ? "" : saltFor(day)}|${day}|${point.host}|${ip}|${ua}`).digest("hex").slice(0, 16) : ""
  return clean({
    ...point,
    country: point.country || found.country, region: point.region || found.region, city: point.city || found.city,
    // Cloudflare's coordinates when nginx got them, else the lookup's
    lat: point.lat || found.lat, lon: point.lon || found.lon,
    asn: found.asn || point.asn, asorg: found.asorg || point.asorg, visitor, ip: recordIp ? ip : ""
  })
}

// One nginx syslog datagram ("<190>Oct  6 10:35:35 spor: {...}") -> { point, seconds }, or null.
// The JSON comes from log_format spor_json (escape=json); host is $server_name, so a spoofed Host
// header can't claim a configured host.
export function fromNginx(message) {
  const start = message.indexOf("{")
  if (start < 0) return null
  let e
  try {
    e = JSON.parse(message.slice(start))
  } catch {
    return null
  }
  if (!e || typeof e !== "object") return null
  let path = ""
  try {
    path = new URL(String(e.uri || "/"), "http://spor.invalid").pathname
  } catch {
    return null
  }
  // a time nginx could have logged (2000 to a day ahead), else now: a wild value would break dates
  const seconds = Number(e.msec)
  const nowSeconds = Date.now() / 1000
  const v = (x) => (x === "-" ? "" : x)
  return {
    seconds: seconds > 946684800 && seconds < nowSeconds + 86400 ? seconds : nowSeconds,
    point: clean({
      host: e.host, path, referer: originOf(e.referer), ua: v(e.ua), country: v(e.country),
      status: e.status, bot: "", origin: originOf(e.origin), method: v(e.method),
      // Cloudflare's visitor-location headers, when that Managed Transform is on
      city: v(e.city), region: v(e.region), lat: v(e.lat), lon: v(e.lon), ip: v(e.ip)
    })
  }
}

// ---- Analytics Engine sync ---------------------------------------------------------------------

const sqlTime = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 19).replace("T", " ")

export function aeWindowQuery(dataset, from, to) {
  if (!/^[A-Za-z0-9_]+$/.test(dataset)) throw new Error("invalid dataset")
  const cols = FIELDS.map((f) => `${AE_COLUMNS[f]} AS ${f}`).join(", ")
  return `SELECT toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS hour, ${cols}, SUM(_sample_interval) AS n FROM ${dataset} WHERE timestamp >= toDateTime('${sqlTime(from)}') AND timestamp < toDateTime('${sqlTime(to)}') GROUP BY hour, ${FIELDS.join(", ")} ORDER BY hour LIMIT ${AE_LIMIT} FORMAT JSON`
}

async function aeQuery(secrets, query, fetchImpl) {
  const res = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${secrets.accountId}/analytics_engine/sql`, {
    method: "POST", headers: { Authorization: `Bearer ${secrets.token}`, "User-Agent": "spor-server" }, body: query
  })
  if (!res.ok) throw new Error(`Analytics Engine SQL answered ${res.status}`)
  return ((await res.json()).data ?? []).map((r) => ({ ...r, hour: Date.parse(String(r.hour).replace(" ", "T") + "Z") / 1000 }))
}

// Pull [from, to) and replace that window in the store, an hour at a time if it fills the LIMIT
async function pullWindow(store, secrets, config, from, to, fetchImpl) {
  let rows = await aeQuery(secrets, aeWindowQuery(config.dataset, from, to), fetchImpl)
  if (rows.length >= AE_LIMIT && to - from > HOUR) {
    rows = []
    for (let h = from; h < to; h += HOUR) {
      const part = await aeQuery(secrets, aeWindowQuery(config.dataset, h, h + HOUR), fetchImpl)
      if (part.length >= AE_LIMIT) console.log(`spor: AE hour ${sqlTime(h)} hit the ${AE_LIMIT}-row cap; that hour is partial`)
      rows.push(...part)
    }
  }
  store.replaceAE(from, to, rows)
  return rows.length
}

// Pull from SYNC_BACK_HOURS before the last synced hour (on the first run, from the start of AE's
// retention) to now, a day window at a time, checkpointing after each. A sync every 5 minutes is one
// query, about 300 of the 10,000 AE reads a day on Workers Free. Catching up never reaches past AE's
// retention, so after any downtime it costs at most 93 windows of up to 25 queries.
export const SYNC_BACK_HOURS = 3
export async function syncAE(store, secrets, config, { now = Date.now() / 1000, fetchImpl = fetch } = {}) {
  const hour = Math.floor(now / HOUR) * HOUR
  const oldest = Math.floor(now / DAY) * DAY - AE_RETENTION_DAYS * DAY
  const synced = store.meta("ae:synced")
  let from = synced === null ? oldest : Math.max(oldest, Math.min(Number(synced), hour) - SYNC_BACK_HOURS * HOUR)
  let pulled = 0
  while (from <= hour) {
    const to = Math.min(hour + HOUR, from + DAY)
    pulled += await pullWindow(store, secrets, config, from, to, fetchImpl)
    store.setMeta("ae:synced", Math.min(to, hour))
    from = to
  }
  return pulled
}

// ---- ingest -------------------------------------------------------------------------------------

async function readLimited(request, max) {
  if (Number(request.headers.get("content-length") || 0) > max) return null
  const reader = request.body?.getReader()
  if (!reader) return ""
  const chunks = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      reader.cancel()
      return null
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString("utf8")
}

export async function ingest(request, { token, config, store }) {
  if (!token) return text(404, "not found")
  const header = request.headers.get("authorization") || ""
  if (!header.startsWith("Bearer ") || !safeEqual(header.slice(7), token)) return text(401, "authentication required")
  if (request.method !== "POST") return text(405, "method not allowed", { Allow: "POST" })
  const body = await readLimited(request, INGEST_MAX_BYTES)
  if (body === null) return text(413, "too large")
  let parsed
  try {
    parsed = JSON.parse(body)
  } catch {
    return text(400, "invalid JSON")
  }
  const list = Array.isArray(parsed) ? parsed : [parsed]
  if (list.length > INGEST_MAX_POINTS) return text(413, "too many points")
  const points = list.map(fromDataPoint)
  if (points.some((p) => !p || !config.local.has(p.host))) return text(400, "every point needs a host listed in config.local")
  const now = Date.now() / 1000
  // the sender's visitor hash is kept; its IP only with recordIp
  for (const p of points) store.addLocal(config.recordIp ? p : { ...p, ip: "" }, "ingest", now)
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } })
}

// ---- server -------------------------------------------------------------------------------------

function parseListen(value, fallback) {
  const m = /^(.*):(\d{1,5})$/.exec(value || fallback)
  if (!m) throw new Error(`invalid listen address ${JSON.stringify(value)} (want host:port)`)
  return { host: m[1].replace(/^\[|\]$/g, ""), port: Number(m[2]) }
}

function toRequest(req, base) {
  const headers = new Headers()
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v)
  const hasBody = req.method !== "GET" && req.method !== "HEAD"
  return new Request(new URL(req.url, base), { method: req.method, headers, body: hasBody ? Readable.toWeb(req) : undefined, duplex: hasBody ? "half" : undefined })
}

// env: DASHBOARD_PASSWORD (required unless SPOR_AUTH=off), SPOR_AUTH, SPOR_DB, SPOR_GEO_DB (default
// geo.db beside SPOR_DB), SPOR_LISTEN, SPOR_SYSLOG, INGEST_TOKEN, CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN,
// SPOR_AE_SYNC_MINUTES
export async function startServer({ spor, env = process.env, fetchImpl = fetch } = {}) {
  let config = null
  try {
    config = requireConfig(spor)
  } catch (error) {
    console.log(`spor: ${error.message}; every request answers 503 until it is fixed`)
  }
  // SPOR_AUTH=off drops Basic auth on / and /api/report, for a server that only a private
  // network can reach (a tailnet-only proxy). Exactly "off": anything else keeps auth on.
  const open = env.SPOR_AUTH === "off"
  if (open) console.log("spor: SPOR_AUTH=off, the dashboard and API need no password; keep the server private")
  const store = openStore(env.SPOR_DB || "spor.db")
  const geo = openGeo(env.SPOR_GEO_DB || join(dirname(env.SPOR_DB || "spor.db"), "geo.db"))
  if (geo) console.log("spor: geo lookups on")
  const listen = parseListen(env.SPOR_LISTEN, "127.0.0.1:2650")
  const timers = []
  let running = null
  let synced = false

  const server = createServer(async (req, res) => {
    let response
    try {
      const request = toRequest(req, `http://${listen.host}`)
      const path = new URL(request.url).pathname
      if (path === "/api/ingest") {
        response = config && (env.DASHBOARD_PASSWORD || open) ? await ingest(request, { token: env.INGEST_TOKEN, config, store }) : text(503, "spor is not configured")
      } else {
        response = await handle(request, {
          ready: true, password: env.DASHBOARD_PASSWORD, open, spor, source: "the spor database", cache: null, credit: geo ? CREDIT : "",
          rows: async (days, host, cfg, filters) => store.rows(days, host, cfg, Date.now(), filters)
        })
      }
    } catch (error) {
      console.log(String(error))
      response = text(500, "internal error")
    }
    res.writeHead(response.status, Object.fromEntries(response.headers))
    res.end(req.method === "HEAD" ? undefined : Buffer.from(await response.arrayBuffer()))
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(listen.port, listen.host, resolve)
  })
  console.log(`spor: dashboard on http://${listen.host}:${server.address().port}`)

  let udp = null
  if (env.SPOR_SYSLOG && config) {
    const at = parseListen(env.SPOR_SYSLOG)
    udp = createSocket(at.host.includes(":") ? "udp6" : "udp4")
    udp.on("message", (msg) => {
      // one bad line must never stop the server
      try {
        const entry = fromNginx(msg.toString("utf8"))
        if (entry && config.local.has(entry.point.host)) {
          store.addLocal(enrich(entry.point, { geo, recordIp: config.recordIp, now: entry.seconds * 1000 }), "nginx", entry.seconds)
        }
      } catch (error) {
        console.log(`spor: dropped a syslog line: ${error.message}`)
      }
    })
    await new Promise((resolve) => udp.bind(at.port, at.host, resolve))
    console.log(`spor: nginx syslog on udp ${at.host}:${udp.address().port} for ${config.local.size} local hosts`)
  }

  if (env.CF_ACCOUNT_ID && env.CF_ANALYTICS_TOKEN && config) {
    const secrets = { accountId: env.CF_ACCOUNT_ID, token: env.CF_ANALYTICS_TOKEN }
    const minutes = Math.max(1, Number(env.SPOR_AE_SYNC_MINUTES) || 5)
    const sync = () => {
      // the first sync (the backfill) is logged; later ones only when they fail
      running ??= syncAE(store, secrets, config, { fetchImpl })
        .then((n) => {
          if (!synced) console.log(`spor: AE sync pulled ${n} rows`)
          synced = true
        })
        .catch((error) => console.log(`spor: AE sync failed: ${error.message}`))
        .finally(() => { running = null })
      return running
    }
    timers.push(setInterval(sync, minutes * 60000))
    sync()
  }

  return {
    server, udp, store,
    port: server.address().port,
    syncing: () => running,
    async stop() {
      for (const t of timers) clearInterval(t)
      await running
      udp?.close()
      await new Promise((resolve) => server.close(resolve))
      store.close()
      geo?.close()
    }
  }
}
