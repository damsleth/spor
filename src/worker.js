import { loadConfig, checkAuth, clampDays, validHost, queries, build, render, toJSON } from "./report.js"

const HEADERS = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex"
}
const CACHE_SECONDS = 300

function text(status, body, extra = {}) {
  return new Response(body, { status, headers: { ...HEADERS, "Content-Type": "text/plain; charset=utf-8", ...extra } })
}

async function cacheKey(origin, accountId, query) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${accountId}\n${query}`))
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")
  return new Request(`${origin}/__spor_cache/${hex}`)
}

// One Analytics Engine SQL query. Raw JSON is cached for 5 minutes so a reload costs no AE reads.
async function sql(env, origin, query) {
  const cache = globalThis.caches?.default
  const key = cache ? await cacheKey(origin, env.CF_ACCOUNT_ID, query) : null
  if (cache) {
    const hit = await cache.match(key)
    if (hit) return (await hit.json()).data ?? []
  }
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
    method: "POST",
    headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`, "Content-Type": "text/plain" },
    body: query
  })
  if (!response.ok) throw new Error(`Analytics Engine SQL ${response.status}`)
  const body = await response.text()
  const data = JSON.parse(body).data ?? []
  if (cache) await cache.put(key, new Response(body, { headers: { "Cache-Control": `max-age=${CACHE_SECONDS}` } }))
  return data
}

export default {
  async fetch(request, env) {
    // fail closed: without every secret there is no dashboard, not an open one
    if (!env.DASHBOARD_PASSWORD || !env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) {
      return text(503, "spor is not configured")
    }
    if (!checkAuth(request.headers.get("authorization"), env.DASHBOARD_PASSWORD)) {
      return text(401, "authentication required", { "WWW-Authenticate": "Basic realm=\"spor\", charset=\"UTF-8\"" })
    }
    if (request.method !== "GET" && request.method !== "HEAD") return text(405, "method not allowed", { Allow: "GET, HEAD" })

    const url = new URL(request.url)
    if (url.pathname !== "/" && url.pathname !== "/api/report") return text(404, "not found")

    let config
    try {
      config = loadConfig(env.SPOR)
    } catch {
      return text(503, "spor config (vars.SPOR) is invalid")
    }
    const days = clampDays(url.searchParams.get("days"))
    const host = validHost(url.searchParams.get("host"), config)
    const q = queries(days, host, config)
    try {
      const names = Object.keys(q)
      const results = await Promise.all(names.map((name) => sql(env, url.origin, q[name])))
      const model = build(Object.fromEntries(names.map((name, i) => [name, results[i]])), config)
      if (url.pathname === "/api/report") {
        return new Response(JSON.stringify(toJSON(model, config, { days, host })), { headers: { ...HEADERS, "Content-Type": "application/json; charset=utf-8" } })
      }
      const html = render(model, { days, host, config, generated: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC" })
      return new Response(html, { headers: { ...HEADERS, "Content-Type": "text/html; charset=utf-8" } })
    } catch (error) {
      console.log(String(error))
      return text(502, "could not read Analytics Engine")
    }
  }
}
