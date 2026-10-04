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
every `hashchange`:

```js
const sendRoute = () => navigator.sendBeacon("/api/spor", JSON.stringify({ route: location.hash.replace(/^#/, "") || "/" }))
sendRoute()
window.addEventListener("hashchange", sendRoute)
```

The beacon is then the only page-view signal, so keep the HTML shell out of the tap. In this
case don't use the page-view `run_worker_first` list above. Serve `/` as a plain asset and let
the Worker see only `/api/spor` and fall-through paths (404s and probes). Otherwise one load
counts twice, as `GET /` and as `VIEW`.

The Worker caps the body while reading it, because the endpoint is unauthenticated. It then
validates the route against a strict pattern and writes it with path `/#<route>` and method
`VIEW`:

```js
// read at most `max` bytes; null if the body is larger
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
    if (size > max) { reader.cancel(); return null }
    chunks.push(value)
  }
  return new TextDecoder().decode(chunks.length === 1 ? chunks[0] : new Uint8Array(chunks.flatMap((c) => [...c])))
}

if (url.pathname === "/api/spor" && request.method === "POST") {
  const body = await readLimited(request, 2048)
  if (body === null) return new Response(null, { status: 413 })
  let route
  try { route = JSON.parse(body).route } catch {}
  if (typeof route !== "string" || !/^\/(about|post\/[a-z0-9-]{1,120})?$/.test(route)) return new Response(null, { status: 400 })
  const point = dataPoint(request, 200)
  point.blobs[0] = `/#${route}`
  point.blobs[7] = "VIEW"
  try { env.SPOR_ANALYTICS?.writeDataPoint(point) } catch {}
  return new Response(null, { status: 204 })
}
```
