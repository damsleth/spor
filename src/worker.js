import { queries } from "./report.js"
import { handle } from "./http.js"

const CACHE_SECONDS = 300

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
    const origin = new URL(request.url).origin
    return handle(request, {
      ready: Boolean(env.CF_ANALYTICS_TOKEN && env.CF_ACCOUNT_ID),
      password: env.DASHBOARD_PASSWORD,
      spor: env.SPOR,
      source: "Analytics Engine",
      rows: async (days, host, config) => {
        const q = queries(days, host, config)
        const names = Object.keys(q)
        const results = await Promise.all(names.map((name) => sql(env, origin, q[name])))
        return Object.fromEntries(names.map((name, i) => [name, results[i]]))
      }
    })
  }
}
