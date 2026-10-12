import { baitKind, sinkable } from "../src/report.js"
import { findToken, readToken, makeToken, bait, internalResponse, INTERNAL } from "./sink.js"

// spor tap for hosts that are not Workers: a home server, a VPS behind nginx, Pages, another
// cloud, anything behind the Cloudflare proxy. This Worker sits on their routes, passes every
// request to the origin untouched (WebSockets and streaming included), and writes one Analytics
// Engine data point with the schema every spor site shares:
// indexes [host], blobs [path, refererOrigin, userAgent, country, status, botCategory, origin, method,
// city, region, asn, asOrganization, visitor, ip, latitude, longitude, sink, sinkContext], doubles [1].
// sink is "bait:<kind>" for a probe that got bait, "use:<kind>" for a request with a canary token,
// "challenge" for /_internal/ without one; sinkContext is the probe a used token came from.
// Coordinates are
// Cloudflare's for the city, rounded to 2 decimals (about 1 km). No query string. A failed write
// never affects the response.
// A route runs in front of a Worker's custom domain too, so wildcard routes count Worker sites as
// well. vars.SELF_COUNTED lists the hosts whose own Worker already writes the point (snippets/):
// those pass through unrecorded, so nothing is counted twice.
// The client IP is stored only when vars.RECORD_IP is true. visitor is a daily hash of host, IP and
// user agent: salted with a random daily salt from the SALTS KV namespace when one is bound (the
// salt expires after two days, so hashes can't be linked across days), unsalted when RECORD_IP is
// true (the IP is stored anyway), and left empty otherwise.
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

export function dataPoint(request, status, { visitor = "", ip = "", sink = "", sinkctx = "" } = {}) {
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
      coord(cf.longitude),
      sink,
      sinkctx.slice(0, 400)
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

export async function visitorId(request, env, ip, now = Date.now()) {
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

// sink: { kind, ctx } for a sinkhole event, which is recorded even for a SELF_COUNTED host: its own
// tap never sees the bait
// only a list counts: a malformed SELF_COUNTED must never throw in front of the origin
const selfCounted = (env, host) => Array.isArray(env.SELF_COUNTED) && env.SELF_COUNTED.includes(host)

export async function record(request, status, env, sink = null) {
  try {
    const host = new URL(request.url).hostname.replace(/\.$/, "")
    if (!env.SPOR_ANALYTICS || (!sink && selfCounted(env, host))) return
    const ip = request.headers.get("cf-connecting-ip") || ""
    const visitor = await visitorId(request, env, ip)
    env.SPOR_ANALYTICS.writeDataPoint(dataPoint(request, status, { visitor, ip: env.RECORD_IP === true ? ip : "", sink: sink?.kind, sinkctx: sink?.ctx }))
  } catch {
    // analytics must never break the site
  }
}

// A canary token in use: record it with the probe it came from, and announce it once an hour per
// token (CANARY_WEBHOOK, an ntfy topic URL say, with CANARY_WEBHOOK_TOKEN as its Bearer token)
const announced = new Map()
// An IP appears in the context and the alert only with RECORD_IP, like everywhere else; a token
// minted while it was on still carries one, which is dropped here when it is off.
async function canaryUsed(request, env, token, status) {
  const ips = env.RECORD_IP === true
  const found = await readToken(env.CANARY_SECRET, token)
  const baitIp = ips && found ? found.ip : ""
  // context: "<bait host>|<bait ip>|<when>|<kind>", or empty for a token this secret can't read
  const ctx = found ? `${found.host}|${baitIp}|${found.at}|${found.kind}` : ""
  await record(request, status, env, { kind: `use:${found?.kind || "unknown"}`, ctx })
  const now = Date.now()
  // { sent } after a delivered alert (quiet for an hour), { sending } while one is out (a minute at
  // most: the call times out after 5 s, and a lost isolate never clears it)
  const last = announced.get(token)
  if (!env.CANARY_WEBHOOK || (last?.sent && now - last.sent < 3600000) || (last?.sending && now - last.sending < 60000)) return
  const attempt = { sending: now }
  announced.set(token, attempt)
  if (announced.size > 1000) announced.clear()
  const url = new URL(request.url)
  const cf = request.cf || {}
  const who = [ips ? request.headers.get("cf-connecting-ip") : "", cf.asOrganization, cf.country].filter(Boolean).join(", ")
  const from = found ? `the ${found.kind} bait on ${found.host}, given${baitIp ? ` to ${baitIp}` : ""} at ${found.at} UTC` : "an unknown bait"
  try {
    const res = await fetch(env.CANARY_WEBHOOK, {
      method: "POST",
      headers: { title: "spor canary used", tags: "rotating_light", ...(env.CANARY_WEBHOOK_TOKEN ? { authorization: `Bearer ${env.CANARY_WEBHOOK_TOKEN}` } : {}) },
      body: `A key from ${from} was used by ${who || "an unknown client"} on ${url.hostname}${url.pathname.slice(0, 64)}`,
      signal: AbortSignal.timeout(5000)
    })
    if (!res.ok) throw new Error(`webhook answered ${res.status}`)
    // quiet for an hour only once the alert is out
    if (announced.get(token) === attempt) announced.set(token, { sent: now })
  } catch (error) {
    // a newer attempt's lock is not ours to clear
    if (announced.get(token) === attempt) announced.delete(token)
    console.log(`spor: canary alert failed: ${error.message}`)
  }
}

// Bait instead of the origin's answer, when the path is a probe, the origin has nothing there (a
// 403, 404 or 410, or an HTML fallback page for a file that is never HTML) and the client isn't
// exempt. A SELF_COUNTED host gets none: its own Worker already counted the origin's answer, so
// bait would count the probe twice.
const NEVER_HTML = ["env", "git", "aws", "npm", "docker"]
async function baitResponse(request, env, path, response) {
  const kind = baitKind(path)
  if (!kind) return null
  const host = new URL(request.url).hostname.replace(/\.$/, "")
  if (selfCounted(env, host)) return null
  const html = (response.headers.get("content-type") || "").includes("text/html")
  const empty = [403, 404, 410].includes(response.status) || (response.status === 200 && html && NEVER_HTML.includes(kind))
  if (!empty || !sinkable({ ua: request.headers.get("user-agent") || "", bot: String(request.cf?.verifiedBotCategory || "") })) return null
  const token = await makeToken(env.CANARY_SECRET, { host, ip: env.RECORD_IP === true ? request.headers.get("cf-connecting-ip") || "" : "", kind })
  const b = bait(kind, host, token)
  if (!b) return null
  response.body?.cancel()
  return {
    response: new Response(b.body, { status: 200, headers: { "content-type": b.type, "cache-control": "no-store" } }),
    record: record(request, 200, env, { kind: `bait:${kind}`, ctx: "" })
  }
}

export default {
  async fetch(request, env, ctx) {
    // after the response: hashing, KV and the webhook stay off the request's path
    const later = (p) => (ctx?.waitUntil ? ctx.waitUntil(p) : p)
    // the sinkhole is off unless vars.SINKHOLE is true, and for a SELF_COUNTED host: its own Worker
    // counts it and decides what to record (the CORS proxy never records its upstream paths, which
    // a token in the URL would put in a sink record). Any failure in it falls back to the origin.
    let path = "/"
    let host = ""
    try {
      const url = new URL(request.url)
      path = url.pathname
      host = url.hostname.replace(/\.$/, "")
    } catch {
      // keep "/"
    }
    const sinkhole = env.SINKHOLE === true && !selfCounted(env, host)
    if (sinkhole) {
      try {
        const token = findToken(request)
        if (token || path.startsWith(INTERNAL)) {
          const answer = internalResponse(Boolean(token))
          await later(token ? canaryUsed(request, env, token, answer.status).catch(() => {}) : record(request, answer.status, env, { kind: "challenge", ctx: "" }))
          return answer
        }
      } catch {
        // fall through to the origin
      }
    }
    const response = await fetch(request)
    if (sinkhole) {
      try {
        const swapped = await baitResponse(request, env, path, response)
        if (swapped) {
          await later(swapped.record)
          return swapped.response
        }
      } catch {
        // the origin's answer stands
      }
    }
    await later(record(request, response.status, env))
    return response
  }
}
