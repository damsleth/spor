# Counting a site that is already a Cloudflare Worker

Sites served by their own Worker write the data point themselves; no route Worker in front.
Both cases below need the Analytics Engine binding in the site's wrangler config. Without it
the tap does nothing (by design it never fails the request), so verify a recorded point after
deploying:

```jsonc
"analytics_engine_datasets": [{ "binding": "SPOR_ANALYTICS", "dataset": "spor_analytics" }]
```

**Static assets only** (no Worker script yet): copy `site-tap.js` to the site as `src/worker.js` and add to its wrangler config:

```jsonc
"main": "src/worker.js",
"assets": {
  "directory": "./public",
  "binding": "ASSETS",
  // the Worker runs for pages only; assets skip it and stay free ("*" crosses "/", "!" wins)
  "run_worker_first": ["/*", "!/*.js", "!/*.mjs", "!/*.css", "!/*.map", "!/*.png", "!/*.jpg", "!/*.jpeg", "!/*.gif",
    "!/*.svg", "!/*.ico", "!/*.webp", "!/*.avif", "!/*.woff", "!/*.woff2", "!/*.ttf", "!/*.otf", "!/*.json",
    "!/*.webmanifest", "!/*.txt", "!/*.xml", "!/*.mp3", "!/*.mp4", "!/*.webm", "!/*.wasm", "!/*.pdf"]
},
"analytics_engine_datasets": [{ "binding": "SPOR_ANALYTICS", "dataset": "spor_analytics" }]
```

**Worker with code**: rename its default export to `const site = {...}` and wrap it,
forwarding `ctx` so `ctx.waitUntil()` and `ctx.passThroughOnException()` keep working:

```js
export default {
  async fetch(request, env, ctx) {
    const response = await site.fetch(request, env, ctx)
    try { env.SPOR_ANALYTICS?.writeDataPoint(dataPoint(request, response.status)) } catch {}
    return response
  }
}
```

with `dataPoint` copied from `../tap/worker.js`. Never record the query string or the client IP.

**Hash-routed single-page apps** (`/#/post/x`): the fragment never reaches the server, and
Cloudflare Web Analytics strips it too. So the client reports the route itself, on load and on
`hashchange`:

```js
const route = location.hash.replace(/^#/, "") || "/"
navigator.sendBeacon("/api/spor", JSON.stringify({ route }))
```

The Worker validates the route against a strict pattern and writes it with path `/#<route>` and
method `VIEW`:

```js
if (url.pathname === "/api/spor" && request.method === "POST") {
  let route
  try { route = JSON.parse((await request.text()).slice(0, 2048)).route } catch {}
  if (typeof route !== "string" || !/^\/(about|post\/[a-z0-9-]{1,120})?$/.test(route)) return new Response(null, { status: 400 })
  const point = dataPoint(request, 200)
  point.blobs[0] = `/#${route}`
  point.blobs[7] = "VIEW"
  try { env.SPOR_ANALYTICS?.writeDataPoint(point) } catch {}
  return new Response(null, { status: 204 })
}
```
