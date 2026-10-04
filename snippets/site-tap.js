// spor tap: one Analytics Engine data point per page request (dataset spor_analytics).
// Schema shared with every spor site: indexes [host], blobs [path, refererOrigin, userAgent,
// country, status, botCategory, origin, method], doubles [1]. No IP, no query string.
// run_worker_first in the wrangler config sends only page requests here; assets skip the Worker.
function originOf(value) {
  if (!value) return ""
  try {
    return new URL(value).origin
  } catch {
    return ""
  }
}

export default {
  async fetch(request, env) {
    const response = await env.ASSETS.fetch(request)
    try {
      const url = new URL(request.url)
      env.SPOR_ANALYTICS?.writeDataPoint({
        indexes: [url.hostname],
        blobs: [
          url.pathname.slice(0, 64),
          originOf(request.headers.get("referer")),
          (request.headers.get("user-agent") || "").slice(0, 256),
          String(request.cf?.country || ""),
          String(response.status),
          String(request.cf?.verifiedBotCategory || ""),
          originOf(request.headers.get("origin")),
          request.method
        ],
        doubles: [1]
      })
    } catch {
      // analytics must never break the site
    }
    return response
  }
}
