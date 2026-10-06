// spor's self-hosted backend: one Node process (built-ins only) with a SQLite store, serving the
// same dashboard and API as the Worker (src/http.js). It is fed by:
//   - nginx, which sends one JSON access-log line per request over syslog (UDP, loopback);
//     see selfhost/nginx-spor-log.conf. Only hosts in config.local are kept.
//   - POST /api/ingest, Bearer INGEST_TOKEN, a data point in the Analytics Engine shape that the
//     tap writes ({ indexes: [host], blobs: [...8] }), or an array of up to 100 of them.
//   - Analytics Engine (when CF_ACCOUNT_ID and CF_ANALYTICS_TOKEN are set): a backfill of everything
//     AE still holds, then the last two days re-pulled every SPOR_AE_SYNC_MINUTES.
// Started by `spor serve`. Put it behind a reverse proxy or `tailscale serve`; it speaks plain HTTP.
import { createServer } from "node:http"
import { createSocket } from "node:dgram"
import { Readable } from "node:stream"
import { requireConfig, safeEqual } from "./report.js"
import { handle, text } from "./http.js"
import { openStore, HOUR, FIELDS } from "./store.js"

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
function clean({ host, path, referer, ua, country, status, bot, origin, method }) {
  const s = (v, max) => (typeof v === "string" ? v : v === undefined || v === null ? "" : String(v)).slice(0, max)
  return {
    host: s(host, 253).toLowerCase(), path: s(path, 64), referer: s(referer, 256), ua: s(ua, 256), country: s(country, 8),
    status: s(status, 3), bot: s(bot, 64), origin: s(origin, 256), method: s(method, 16)
  }
}

// the tap's Analytics Engine data point -> store fields
export function fromDataPoint(point) {
  if (!point || !Array.isArray(point.indexes) || !Array.isArray(point.blobs)) return null
  const [path, referer, ua, country, status, bot, origin, method] = point.blobs
  return clean({ host: point.indexes[0], path, referer, ua, country, status, bot, origin, method })
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
  const seconds = Number(e.msec)
  const v = (x) => (x === "-" ? "" : x)
  return {
    seconds: Number.isFinite(seconds) && seconds > 0 ? seconds : Date.now() / 1000,
    point: clean({
      host: e.host, path, referer: originOf(e.referer), ua: v(e.ua), country: v(e.country),
      status: e.status, bot: "", origin: originOf(e.origin), method: v(e.method)
    })
  }
}

// ---- Analytics Engine sync ---------------------------------------------------------------------

const sqlTime = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 19).replace("T", " ")

export function aeWindowQuery(dataset, from, to) {
  if (!/^[A-Za-z0-9_]+$/.test(dataset)) throw new Error("invalid dataset")
  const cols = "index1 AS host, blob1 AS path, blob2 AS referer, blob3 AS ua, blob4 AS country, blob5 AS status, blob6 AS bot, blob7 AS origin, blob8 AS method"
  return `SELECT toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS hour, ${cols}, SUM(_sample_interval) AS n FROM ${dataset} WHERE timestamp >= toDateTime('${sqlTime(from)}') AND timestamp < toDateTime('${sqlTime(to)}') GROUP BY hour, ${FIELDS.join(", ")} ORDER BY hour LIMIT ${AE_LIMIT} FORMAT JSON`
}

async function aeQuery(secrets, query, fetchImpl) {
  const res = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${secrets.accountId}/analytics_engine/sql`, {
    method: "POST", headers: { Authorization: `Bearer ${secrets.token}`, "User-Agent": "spor-server" }, body: query
  })
  if (!res.ok) throw new Error(`Analytics Engine SQL answered ${res.status}`)
  return ((await res.json()).data ?? []).map((r) => ({ ...r, hour: Date.parse(String(r.hour).replace(" ", "T") + "Z") / 1000 }))
}

// Pull [from, to) a day at a time (an hour at a time if a day fills the LIMIT) and replace those
// windows in the store. The first run backfills AE's retention, later runs re-pull two days.
export async function syncAE(store, secrets, config, { now = Date.now() / 1000, fetchImpl = fetch } = {}) {
  const today = Math.floor(now / DAY) * DAY
  const synced = store.meta("ae:synced")
  let day = synced === null ? today - AE_RETENTION_DAYS * DAY : Math.min(Number(synced), today - DAY)
  let pulled = 0
  for (; day <= today; day += DAY) {
    let rows = await aeQuery(secrets, aeWindowQuery(config.dataset, day, day + DAY), fetchImpl)
    if (rows.length >= AE_LIMIT) {
      rows = []
      for (let h = day; h < day + DAY; h += HOUR) {
        const part = await aeQuery(secrets, aeWindowQuery(config.dataset, h, h + HOUR), fetchImpl)
        if (part.length >= AE_LIMIT) console.log(`spor: AE hour ${sqlTime(h)} hit the ${AE_LIMIT}-row cap; that hour is partial`)
        rows.push(...part)
      }
    }
    store.replaceAE(day, day + DAY, rows)
    pulled += rows.length
  }
  store.setMeta("ae:synced", today - DAY)
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
  for (const p of points) store.addLocal(p, "ingest", now)
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

// env: DASHBOARD_PASSWORD (required unless SPOR_AUTH=off), SPOR_AUTH, SPOR_DB, SPOR_LISTEN,
// SPOR_SYSLOG, INGEST_TOKEN, CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN, SPOR_AE_SYNC_MINUTES
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
          ready: true, password: env.DASHBOARD_PASSWORD, open, spor, source: "the spor database", cache: null,
          rows: async (days, host, cfg) => store.rows(days, host, cfg)
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
      const entry = fromNginx(msg.toString("utf8"))
      if (entry && config.local.has(entry.point.host)) store.addLocal(entry.point, "nginx", entry.seconds)
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
    }
  }
}
