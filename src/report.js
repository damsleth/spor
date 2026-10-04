// spor: pure logic for the dashboard, API and CLI: config, SQL, classification, rendering, auth.
// Import-free so node:test loads it directly. Every blob in the dataset is
// attacker-written (paths, user agents, referers), so all of it is escaped.

// Instance config comes from the Worker var SPOR (wrangler.jsonc "vars": { "SPOR": {...} }),
// so this file holds no hostnames. See wrangler.example.jsonc.
export function loadConfig(raw) {
  const c = typeof raw === "string" ? JSON.parse(raw) : (raw || {})
  const dataset = String(c.dataset || "spor_analytics")
  if (!/^[A-Za-z0-9_]+$/.test(dataset)) throw new Error("spor: config.dataset must match [A-Za-z0-9_]+")
  const services = Object.fromEntries(Object.entries(c.services || {}).map(([h, d]) => [String(h).toLowerCase(), String(d)]))
  return {
    title: String(c.title || "spor"),
    dataset,
    services,
    hosts: Object.keys(services),
    proxyHosts: new Set((c.proxyHosts || []).map((h) => String(h).toLowerCase()))
  }
}

export const DEFAULT_DAYS = 7
export const MAX_DAYS = 31
export const OK_LIMIT = 2000
const TOP = 10

const ASSET = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|map|json|webmanifest|txt|md)$/i
const BOT_UA = /bot|crawl|spider|slurp|curl|wget|python|httpx|go-http|java\/|okhttp|headless|scrapy|facebookexternalhit|preview|monitor|uptime|zgrab|masscan|nuclei|palo alto|censys|shodan|expanse|internet-measurement|scanner/i
const PROBE = /wp-|\.php|\.env|\/\.git|xmlrpc|\/admin|\/cgi-bin|\/vendor\/|\/\.well-known\/security/i
// a proxy target is /<hostname>; scanners' /wp.php or /.well-known only look like one
const TARGET = /^\/[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i

// ---- input -------------------------------------------------------------------------------

export function clampDays(value) {
  if (typeof value !== "string" || !/^\d{1,3}$/.test(value)) return DEFAULT_DAYS
  return Math.min(MAX_DAYS, Math.max(1, Number(value)))
}

export function validHost(value, config) {
  return config.hosts.includes(value) ? value : null
}

// days, host and dataset are validated, so the only interpolated values are an int,
// an allowlisted host and a [A-Za-z0-9_] identifier
export function queries(days, host, config) {
  const d = clampDays(String(days))
  const h = validHost(host, config)
  const from = `FROM ${config.dataset} WHERE timestamp >= NOW() - INTERVAL '${d}' DAY` + (h ? ` AND index1 = '${h}'` : "")
  const n = "SUM(_sample_interval) AS n"
  return {
    totals: `SELECT index1 AS host, blob5 AS status, ${n} ${from} GROUP BY host, status FORMAT JSON`,
    daily: `SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day, index1 AS host, ${n} ${from} GROUP BY day, host ORDER BY day FORMAT JSON`,
    ok: `SELECT index1 AS host, blob1 AS path, blob2 AS referer, blob3 AS ua, blob4 AS country, blob6 AS bot, blob8 AS method, ${n} ${from} AND blob5 >= '200' AND blob5 < '300' AND blob3 != '' GROUP BY host, path, referer, ua, country, bot, method ORDER BY n DESC LIMIT ${OK_LIMIT} FORMAT JSON`,
    paths: `SELECT index1 AS host, blob1 AS path, blob5 AS status, ${n} ${from} GROUP BY host, path, status ORDER BY n DESC LIMIT 500 FORMAT JSON`,
    origins: `SELECT index1 AS host, blob7 AS origin, ${n} ${from} AND blob7 != '' GROUP BY host, origin ORDER BY n DESC LIMIT 50 FORMAT JSON`
  }
}

// ---- classification ----------------------------------------------------------------------

export function isBot(row) {
  return Boolean(row.bot) || !row.ua || BOT_UA.test(row.ua)
}

export function isAsset(path) {
  return ASSET.test(path || "")
}

export function browser(ua) {
  for (const [name, pattern] of [["Edge", /Edg\//], ["Firefox", /Firefox\//], ["Chrome", /Chrome\//], ["Safari", /Safari\//]]) {
    if (pattern.test(ua)) return name
  }
  return "other"
}

function externalReferer(row) {
  if (!row.referer) return ""
  const host = row.referer.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]
  return host === row.host ? "" : row.referer
}

export function build({ totals = [], daily = [], ok = [], paths = [], origins = [] }, config) {
  const hosts = new Map()
  const get = (name) => {
    if (!hosts.has(name)) {
      hosts.set(name, {
        host: name, requests: 0, ok2xx: 0, humans2xx: 0, pageviews: 0, bots: 0, status: new Map(), daily: new Map(), pages: new Map(),
        referers: new Map(), countries: new Map(), browsers: new Map(), probes: new Map(), targets: new Map(), origins: new Map()
      })
    }
    return hosts.get(name)
  }
  const add = (map, key, n) => map.set(key, (map.get(key) || 0) + n)
  const num = (value) => Number(value) || 0

  for (const r of totals) {
    const h = get(r.host)
    h.requests += num(r.n)
    if (String(r.status) >= "200" && String(r.status) < "300") h.ok2xx += num(r.n)
    add(h.status, String(r.status), num(r.n))
  }
  for (const r of daily) add(get(r.host).daily, String(r.day).slice(0, 10), num(r.n))
  for (const r of ok) {
    const h = get(r.host)
    const n = num(r.n)
    if (isBot(r)) continue
    h.humans2xx += n
    if (isAsset(r.path) || !(r.method === "GET" || r.method === "VIEW")) continue
    h.pageviews += n
    add(h.pages, r.path, n)
    add(h.countries, r.country || "??", n)
    add(h.browsers, browser(r.ua), n)
    const ref = externalReferer(r)
    if (ref) add(h.referers, ref, n)
  }
  for (const r of paths) {
    const h = get(r.host)
    const n = num(r.n)
    if (r.status === "404" || PROBE.test(r.path)) add(h.probes, r.path, n)
    if (config.proxyHosts.has(r.host) && TARGET.test(r.path) && !PROBE.test(r.path) && !isAsset(r.path)) add(h.targets, r.path, n)
  }
  for (const r of origins) add(get(r.host).origins, r.origin, num(r.n))

  // bots = every 2xx that wasn't a human row; empty-UA rows never reach the detail query
  for (const h of hosts.values()) h.bots = Math.max(0, h.ok2xx - h.humans2xx)
  const model = [...hosts.values()].sort((a, b) => b.requests - a.requests)
  // the detail query is capped: if it came back full, human counts are a lower bound
  model.partial = ok.length >= OK_LIMIT
  return model
}

// The model as plain JSON (Maps become [key, count] lists, top first), for /api/report and the CLI
export function toJSON(model, config, { days, host } = {}) {
  const top = (map) => [...map.entries()].sort((a, b) => b[1] - a[1])
  return {
    days, host: host || null, partial: Boolean(model.partial),
    hosts: model.map((h) => ({
      host: h.host, description: config.services[h.host] || null,
      requests: h.requests, ok2xx: h.ok2xx, pageviews: h.pageviews, bots: h.bots,
      status: top(h.status), daily: [...h.daily.entries()].sort(), pages: top(h.pages), referers: top(h.referers),
      countries: top(h.countries), browsers: top(h.browsers), probes: top(h.probes), targets: top(h.targets), origins: top(h.origins)
    }))
  }
}

// ---- rendering ---------------------------------------------------------------------------

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[c])
}

function top(map) {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP)
}

function table(title, map) {
  if (!map.size) return ""
  const rows = top(map).map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td class="n">${v}</td></tr>`).join("")
  return `<table><caption>${escapeHtml(title)}</caption>${rows}</table>`
}

function windowDays(days, today) {
  const end = Date.parse(`${today}T00:00:00Z`)
  return Array.from({ length: days }, (_, i) => new Date(end - (days - 1 - i) * 86400000).toISOString().slice(0, 10))
}

function bars(daily, window) {
  const days = window.map((day) => [day, daily.get(day) || 0])
  if (!daily.size) return ""
  const max = Math.max(1, ...days.map(([, v]) => v))
  const cols = days.map(([day, v]) => `<div class="bar" style="height:${Math.max(2, Math.round((v / max) * 100))}%" title="${escapeHtml(day)}: ${v}"></div>`).join("")
  return `<div class="bars" aria-label="requests per day">${cols}</div>`
}

function hostSection(h, window, services) {
  const status = top(h.status).map(([k, v]) => `${escapeHtml(k)}&nbsp;${v}`).join(" · ")
  const share = h.ok2xx ? Math.round((h.bots / h.ok2xx) * 100) : 0
  return `<section>
<h2>${escapeHtml(h.host)}${services[h.host] ? ` <span class="desc">${escapeHtml(services[h.host])}</span>` : ""}</h2>
<p class="summary"><b>${h.requests}</b> requests · <b>${h.pageviews}</b> human page views · ${share}% of 2xx from bots</p>
<p class="status">status: ${status}</p>
${bars(h.daily, window)}
<div class="grid">
${table("pages", h.pages)}${table("referers", h.referers)}${table("countries", h.countries)}${table("browsers", h.browsers)}${table("404s and probes", h.probes)}${table("proxy targets", h.targets)}${table("proxy callers (Origin)", h.origins)}
</div>
</section>`
}

export function render(model, { days, host, generated, config, today = new Date().toISOString().slice(0, 10) }) {
  const services = config.services
  const window = windowDays(days, today)
  const link = (d, hst) => `?days=${d}${hst ? `&amp;host=${encodeURIComponent(hst)}` : ""}`
  const dayLinks = [1, 7, 31].map((d) => d === days ? `<b>${d}d</b>` : `<a href="${link(d, host)}">${d}d</a>`).join(" ")
  const hostLinks = [`<a href="${link(days, null)}">all</a>`, ...model.map((h) => `<a href="${link(days, h.host)}"${services[h.host] ? ` title="${escapeHtml(services[h.host])}"` : ""}>${escapeHtml(h.host)}</a>`)].join(" ")
  const total = model.reduce((s, h) => s + h.requests, 0)
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escapeHtml(config.title)}</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#e3e3e3;--bar:#3b6fd8}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e8e8e8;--muted:#999;--line:#2c2c2c;--bar:#6c9cff}}
body{margin:0 auto;max-width:1100px;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
a{color:var(--bar)}h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 4px}h2 .desc{font-weight:400;color:var(--muted);font-size:14px;margin-left:6px}
.muted,.status{color:var(--muted)}section{border-top:1px solid var(--line);padding-top:4px}
.bars{display:flex;align-items:flex-end;gap:2px;height:48px;margin:8px 0}.bar{flex:1;background:var(--bar);min-width:3px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
table{border-collapse:collapse;width:100%;table-layout:fixed}caption{text-align:left;font-weight:600;padding:4px 0}
td{border-bottom:1px solid var(--line);padding:2px 4px;overflow-wrap:anywhere}td.n{width:60px;text-align:right;font-variant-numeric:tabular-nums}
</style></head><body>
<h1>${escapeHtml(config.title)}</h1>
<p class="muted">${total} requests · last ${days} day${days === 1 ? "" : "s"}${host ? ` · ${escapeHtml(host)}` : ""} · generated ${escapeHtml(generated)} · cached up to 5 min</p>
<p>${dayLinks} · ${hostLinks}</p>
${model.partial ? `<p class="muted">Breakdowns are partial: the detail query hit its ${OK_LIMIT}-group cap, so human counts are a lower bound.</p>` : ""}
${model.length ? model.map((h) => hostSection(h, window, services)).join("\n") : "<p>No data in this window.</p>"}
</body></html>`
}

// ---- auth --------------------------------------------------------------------------------

export function safeEqual(a, b) {
  const x = new TextEncoder().encode(a)
  const y = new TextEncoder().encode(b)
  let diff = x.length ^ y.length
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0)
  return diff === 0
}

// Basic auth; the user name is ignored, only the password counts
export function checkAuth(header, password) {
  if (!password || typeof header !== "string") return false
  const match = /^Basic ([A-Za-z0-9+/]+=*)$/.exec(header.trim())
  if (!match) return false
  let decoded
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0)))
  } catch {
    return false
  }
  const colon = decoded.indexOf(":")
  if (colon < 0) return false
  return safeEqual(decoded.slice(colon + 1), password)
}
