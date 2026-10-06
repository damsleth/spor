// spor's HTTP surface, shared by the Worker (src/worker.js) and the self-hosted server
// (src/server.js): fail closed, auth first, no-store everywhere, the dashboard at / and the JSON
// model at /api/report. A backend only supplies `rows`, the five result sets build() expects.
import { requireConfig, checkAuth, clampDays, validHost, build, render, toJSON } from "./report.js"

export const HEADERS = {
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex"
}

export function text(status, body, extra = {}) {
  return new Response(body, { status, headers: { ...HEADERS, "Content-Type": "text/plain; charset=utf-8", ...extra } })
}

// ready: every secret the backend needs is set. rows(days, host, config) resolves to
// { totals, daily, ok, paths, origins }. source names the store in the 502 message.
export async function handle(request, { ready, password, spor, rows, source, cache }) {
  // fail closed: without every secret there is no dashboard, not an open one
  if (!ready || !password) return text(503, "spor is not configured")
  if (!checkAuth(request.headers.get("authorization"), password)) {
    return text(401, "authentication required", { "WWW-Authenticate": "Basic realm=\"spor\", charset=\"UTF-8\"" })
  }
  if (request.method !== "GET" && request.method !== "HEAD") return text(405, "method not allowed", { Allow: "GET, HEAD" })

  const url = new URL(request.url)
  if (url.pathname !== "/" && url.pathname !== "/api/report") return text(404, "not found")

  let config
  try {
    config = requireConfig(spor)
  } catch {
    return text(503, "spor config (vars.SPOR) is missing or invalid")
  }
  const days = clampDays(url.searchParams.get("days"))
  const host = validHost(url.searchParams.get("host"), config)
  try {
    const model = build(await rows(days, host, config), config)
    if (url.pathname === "/api/report") {
      return new Response(JSON.stringify(toJSON(model, config, { days, host })), { headers: { ...HEADERS, "Content-Type": "application/json; charset=utf-8" } })
    }
    const html = render(model, { days, host, config, cache, generated: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC" })
    return new Response(html, { headers: { ...HEADERS, "Content-Type": "text/html; charset=utf-8" } })
  } catch (error) {
    console.log(String(error))
    return text(502, `could not read ${source}`)
  }
}
