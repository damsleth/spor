// spor tap: one Analytics Engine data point per page request (dataset spor_analytics), for a site
// that is a Worker with static assets. Copy to the site as src/worker.js; see README.md here.
// Schema shared with every spor site: indexes [host], blobs [path, refererOrigin, userAgent,
// country, status, botCategory, origin, method, city, region, asn, asOrganization, visitor, ip,
// latitude, longitude],
// doubles [1]. No query string. The IP and the visitor hash follow vars.RECORD_IP and a SALTS KV
// binding exactly as in spor's tap/worker.js, which this copies.
// run_worker_first in the wrangler config sends only page requests here; assets skip the Worker.
function originOf(value) {
  if (!value) return ""
  try {
    return new URL(value).origin
  } catch {
    return ""
  }
}

// a coordinate as text with 2 decimals, or "" when Cloudflare has none
const coord = (v) => (v === undefined || v === null || v === "" || !Number.isFinite(Number(v)) ? "" : Number(v).toFixed(2))

function dataPoint(request, status, { visitor = "", ip = "" } = {}) {
  const url = new URL(request.url)
  const cf = request.cf || {}
  return {
    // one name per host: "example.com." (a fully qualified name some clients send) is example.com
    indexes: [url.hostname.replace(/\.$/, "")],
    blobs: [
      url.pathname.slice(0, 64),
      originOf(request.headers.get("referer")),
      (request.headers.get("user-agent") || "").slice(0, 256),
      String(cf.country || ""),
      String(status),
      String(cf.verifiedBotCategory || ""),
      originOf(request.headers.get("origin")),
      request.method,
      String(cf.city || "").slice(0, 64),
      String(cf.region || "").slice(0, 64),
      cf.asn ? String(cf.asn) : "",
      String(cf.asOrganization || "").slice(0, 64),
      visitor,
      ip.slice(0, 45),
      coord(cf.latitude),
      coord(cf.longitude)
    ],
    doubles: [1]
  }
}

// One salt per UTC day, shared by every isolate through KV. Concurrent requests in this isolate
// share one lookup, and the cached salt is re-read every 10 minutes.
// ponytail: two isolates that both find no salt on a new day each write one; KV keeps the last, and
// both re-read it within 10 minutes, so a visitor can count twice in that first stretch. A single
// writer (a Durable Object) would close that gap.
const SALT_TTL = 600000
let saltCache = { day: "", at: 0, salt: null }
function dailySalt(kv, day, now) {
  if (saltCache.day === day && now - saltCache.at < SALT_TTL && saltCache.salt) return saltCache.salt
  const salt = (async () => {
    let value = await kv.get(`salt:${day}`)
    if (!value) {
      value = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("")
      await kv.put(`salt:${day}`, value, { expirationTtl: 2 * 86400 })
    }
    return value
  })()
  saltCache = { day, at: now, salt }
  // a failed lookup is retried by the next request, not cached
  salt.catch(() => { if (saltCache.salt === salt) saltCache = { day: "", at: 0, salt: null } })
  return salt
}

async function visitorId(request, env, ip, now = Date.now()) {
  if (!ip) return ""
  const day = new Date(now).toISOString().slice(0, 10)
  let salt
  if (env.RECORD_IP === true) salt = ""
  else if (env.SALTS) salt = await dailySalt(env.SALTS, day, now)
  else return ""
  // the same input as spor's server hashes: the user agent as stored, the IP lowercased
  const ua = (request.headers.get("user-agent") || "").slice(0, 256)
  // the host as the point stores it, without a trailing dot, so example.com. is the same visitor
  const input = `${salt}|${day}|${new URL(request.url).hostname.replace(/\.$/, "")}|${ip.toLowerCase()}|${ua}`
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input))
  return [...new Uint8Array(digest).slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("")
}

async function record(request, status, env) {
  try {
    if (!env.SPOR_ANALYTICS) return
    const ip = request.headers.get("cf-connecting-ip") || ""
    const visitor = await visitorId(request, env, ip)
    env.SPOR_ANALYTICS.writeDataPoint(dataPoint(request, status, { visitor, ip: env.RECORD_IP === true ? ip : "" }))
  } catch {
    // analytics must never break the site
  }
}

export default {
  async fetch(request, env, ctx) {
    const response = await env.ASSETS.fetch(request)
    if (ctx?.waitUntil) ctx.waitUntil(record(request, response.status, env))
    else await record(request, response.status, env)
    return response
  }
}
