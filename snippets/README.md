# Counting a site that is already a Cloudflare Worker

Sites served by their own Worker write the data point themselves; no route Worker in front.

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

**Worker with code**: rename its default export to `const site = {...}` and wrap it:

```js
export default {
  async fetch(request, env) {
    const response = await site.fetch(request, env)
    try { env.SPOR_ANALYTICS?.writeDataPoint(dataPoint(request, response.status)) } catch {}
    return response
  }
}
```

with `dataPoint` copied from `../tap/worker.js`. Never record the query string or the client IP.

**Hash-routed single-page apps** (`/#/post/x`): the fragment never reaches the server and Cloudflare Web Analytics strips it too. Send a `navigator.sendBeacon("/api/spor", {route})` from the client on load and `hashchange`, validate the route in the Worker against a strict pattern, and write it with path `/#<route>` and method `VIEW`.
