// spor tap for hosts that are not Workers: a home server, a VPS behind nginx, Pages, another
// cloud, anything behind the Cloudflare proxy. This Worker sits on their routes, passes every
// request to the origin untouched (WebSockets and streaming included), and writes one Analytics
// Engine data point with the schema every spor site shares:
// indexes [host], blobs [path, refererOrigin, userAgent, country, status, botCategory, origin, method],
// doubles [1]. No IP, no query string. A failed write never affects the response.
function originOf(value) {
  if (!value) return ""
  try {
    return new URL(value).origin
  } catch {
    return ""
  }
}

export function dataPoint(request, status) {
  const url = new URL(request.url)
  return {
    indexes: [url.hostname],
    blobs: [
      url.pathname.slice(0, 64),
      originOf(request.headers.get("referer")),
      (request.headers.get("user-agent") || "").slice(0, 256),
      String(request.cf?.country || ""),
      String(status),
      String(request.cf?.verifiedBotCategory || ""),
      originOf(request.headers.get("origin")),
      request.method
    ],
    doubles: [1]
  }
}

export default {
  async fetch(request, env) {
    const response = await fetch(request)
    try {
      env.SPOR_ANALYTICS?.writeDataPoint(dataPoint(request, response.status))
    } catch {
      // analytics must never break the site
    }
    return response
  }
}
