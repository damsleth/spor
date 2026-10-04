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

// A top-N table; every row carries an inline bar proportional to the largest row
function table(title, map) {
  if (!map.size) return ""
  const rows = top(map)
  const max = Math.max(1, rows[0][1])
  const body = rows.map(([k, v]) => `<tr><td><div class="cell"><i style="width:${Math.max(1, Math.round((v / max) * 100))}%"></i><span>${escapeHtml(k)}</span></div></td><td class="n">${v}</td></tr>`).join("")
  return `<table><caption>${escapeHtml(title)}</caption>${body}</table>`
}

function windowDays(days, today) {
  const end = Date.parse(`${today}T00:00:00Z`)
  return Array.from({ length: days }, (_, i) => new Date(end - (days - 1 - i) * 86400000).toISOString().slice(0, 10))
}

const WIDTH = 200
// Zero-filled per-day bars as inline SVG; one <rect> (with a hover <title>) per day in the window
function bars(daily, window, label, tall = false) {
  if (!daily.size) return ""
  const series = window.map((day) => [day, daily.get(day) || 0])
  const max = Math.max(1, ...series.map(([, v]) => v))
  const height = 40
  const step = WIDTH / series.length
  const bw = Math.min(12, Math.max(1, +(step * 0.6).toFixed(1)))
  const rects = series.map(([day, v], i) => {
    const h = v ? Math.max(2, Math.round((v / max) * (height - 2))) : 1
    return `<rect x="${+(i * step + (step - bw) / 2).toFixed(1)}" y="${height - h}" width="${bw}" height="${h}"${v ? "" : ` class="z"`}><title>${escapeHtml(day)}: ${v}</title></rect>`
  }).join("")
  const first = window[0].slice(5)
  const last = window[window.length - 1].slice(5)
  return `<svg class="spark${tall ? " tall" : ""}" viewBox="0 0 ${WIDTH} ${height}" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(label)}: ${max} peak per day, ${escapeHtml(window[0])} to ${escapeHtml(window[window.length - 1])}">${rects}</svg>
<div class="axis"><span>${escapeHtml(first)}</span><span>peak ${max}/day</span><span>${escapeHtml(last)}</span></div>`
}

// Status-code mix: one stacked segment per status class (2xx/3xx/4xx/5xx/other), with a text legend
function statusMix(status) {
  const total = [...status.values()].reduce((s, v) => s + v, 0)
  if (!total) return ""
  const classes = new Map()
  for (const [k, v] of status) {
    const c = /^[2-5]\d\d$/.test(k) ? `c${k[0]}` : "co"
    classes.set(c, (classes.get(c) || 0) + v)
  }
  const segs = [...classes].sort().map(([c, v]) => `<i class="${c}" style="width:${(v / total * 100).toFixed(1)}%"></i>`).join("")
  const legend = top(status).map(([k, v]) => `<span class="${/^[2-5]\d\d$/.test(k) ? `c${k[0]}` : "co"}"><b>${escapeHtml(k)}</b> ${v}</span>`).join("")
  const summary = [...classes].sort().map(([c, v]) => `${c === "co" ? "other" : `${c[1]}xx`} ${Math.round(v / total * 100)}%`).join(", ")
  return `<div class="mix" role="img" aria-label="status mix: ${escapeHtml(summary)}">${segs}</div><p class="legend">${legend}</p>`
}

const fmt = (n) => n.toLocaleString("en-US")

function hostSection(h, window, services) {
  const share = h.ok2xx ? Math.round((h.bots / h.ok2xx) * 100) : 0
  const desc = services[h.host]
  return `<section class="card${h.pageviews ? "" : " quiet"}">
<header><h2>${escapeHtml(h.host)}${desc ? ` <span class="desc">${escapeHtml(desc)}</span>` : ""}</h2></header>
<p class="summary"><b>${fmt(h.requests)}</b> requests · <b>${fmt(h.pageviews)}</b> human page views · ${share}% of 2xx from bots</p>
${bars(h.daily, window, `${h.host} requests per day`)}
${statusMix(h.status)}
<div class="grid">
${table("pages", h.pages)}${table("referers", h.referers)}${table("countries", h.countries)}${table("browsers", h.browsers)}${table("404s and probes", h.probes)}${table("proxy targets", h.targets)}${table("proxy callers (Origin)", h.origins)}
</div>
</section>`
}

const CSS = `:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#14171f;--muted:#5d6572;--line:#e6e8ec;--soft:#f0f2f5;--accent:#2f62d9;--accent-soft:rgba(47,98,217,.12);--c2:#2a8f5b;--c3:#2f62d9;--c4:#c27a10;--c5:#cc3b3b;--co:#8a919d}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f14;--card:#161a22;--fg:#e9ecf2;--muted:#9aa3b2;--line:#262b36;--soft:#1d222c;--accent:#7aa2ff;--accent-soft:rgba(122,162,255,.16);--c2:#4fc08a;--c3:#7aa2ff;--c4:#e0a43c;--c5:#f0716f;--co:#8a919d}}
*{box-sizing:border-box}
body{margin:0 auto;max-width:1120px;padding:24px 16px 48px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-text-size-adjust:100%}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:22px;font-weight:650;letter-spacing:-.01em;margin:0}
.muted{color:var(--muted)}.top p{margin:4px 0 0;font-size:13px}
.bar{display:flex;flex-wrap:wrap;gap:12px 20px;align-items:center;margin:16px 0 20px}
.seg{display:inline-flex;background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:2px}
.seg a,.seg b{padding:4px 12px;border-radius:6px;font-weight:500;color:var(--muted);text-decoration:none}
.seg b{background:var(--card);color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.12)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chips a{padding:2px 10px;border:1px solid var(--line);border-radius:999px;font-size:13px;color:var(--muted);background:var(--card)}
.chips a:hover{color:var(--fg);text-decoration:none;border-color:var(--muted)}
.chips b{padding:2px 10px;border-radius:999px;font-size:13px;background:var(--accent);color:var(--bg)}
.note{border:1px solid var(--c4);border-left-width:4px;background:var(--card);border-radius:8px;padding:8px 12px;margin:0 0 16px;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:12px}
.tile{padding:14px 16px;min-width:0}
.tile .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tile .v{font-size:28px;font-weight:650;letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.2}
.tile .s{font-size:12px;color:var(--muted)}
.card{padding:16px;margin-bottom:16px}
.cap{margin:0 0 8px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.card.quiet{opacity:.72}
h2{font-size:16px;font-weight:650;margin:0;overflow-wrap:anywhere}h2 .desc{display:block;font-weight:400;color:var(--muted);font-size:13px}
.summary{margin:8px 0 12px;color:var(--muted)}.summary b{color:var(--fg);font-variant-numeric:tabular-nums}
.spark{display:block;width:100%;height:56px;fill:var(--accent)}.spark.tall{height:40px}.spark rect{rx:1}.spark rect.z{fill:var(--line)}.spark rect:hover{opacity:.7}
.axis{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin:2px 0 12px}
.mix{display:flex;gap:2px;height:8px;border-radius:4px;overflow:hidden;background:var(--soft)}
.mix i{display:block;height:100%}
.c2{background:var(--c2)}.c3{background:var(--c3)}.c4{background:var(--c4)}.c5{background:var(--c5)}.co{background:var(--co)}
.legend{display:flex;flex-wrap:wrap;gap:2px 12px;margin:6px 0 16px;font-size:12px;color:var(--muted)}
.legend span{background:none!important;padding-left:12px;position:relative;font-variant-numeric:tabular-nums}
.legend span::before{content:"";position:absolute;left:0;top:6px;width:8px;height:8px;border-radius:2px;background:currentColor}
.legend .c2::before{background:var(--c2)}.legend .c3::before{background:var(--c3)}.legend .c4::before{background:var(--c4)}.legend .c5::before{background:var(--c5)}.legend .co::before{background:var(--co)}
.legend b{color:var(--fg);font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:16px 24px}
table{align-self:start;border-collapse:collapse;width:100%;table-layout:fixed}
caption{text-align:left;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:0 0 4px}
td{padding:1px 0;vertical-align:middle}
td.n{width:56px;text-align:right;font-variant-numeric:tabular-nums;padding-left:8px}
.cell{position:relative;padding:2px 6px;border-radius:4px;overflow:hidden}
.cell i{position:absolute;left:0;top:0;bottom:0;background:var(--accent-soft);border-radius:4px}
.cell span{position:relative;display:block;overflow-wrap:anywhere}
.empty{text-align:center;padding:48px 0}
@media (max-width:520px){body{padding:16px 12px 32px}.tile .v{font-size:24px}.card{padding:12px}}`

export function render(model, { days, host, generated, config, today = new Date().toISOString().slice(0, 10) }) {
  const services = config.services
  const window = windowDays(days, today)
  const link = (d, hst) => `?days=${d}${hst ? `&amp;host=${encodeURIComponent(hst)}` : ""}`
  const dayLinks = [1, 7, 31].map((d) => d === days ? `<b aria-current="true">${d}d</b>` : `<a href="${link(d, host)}">${d}d</a>`).join("")
  const hostLinks = [host ? `<a href="${link(days, null)}">all</a>` : `<b aria-current="true">all</b>`, ...model.map((h) => `<a href="${link(days, h.host)}"${services[h.host] ? ` title="${escapeHtml(services[h.host])}"` : ""}>${escapeHtml(h.host)}</a>`)].join("")
  const total = model.reduce((s, h) => s + h.requests, 0)
  const views = model.reduce((s, h) => s + h.pageviews, 0)
  const ok = model.reduce((s, h) => s + h.ok2xx, 0)
  const bots = model.reduce((s, h) => s + h.bots, 0)
  const share = ok ? Math.round((bots / ok) * 100) : 0
  const sum = new Map()
  for (const h of model) for (const [d, n] of h.daily) sum.set(d, (sum.get(d) || 0) + n)
  const tiles = `<div class="tiles">
<div class="tile"><div class="l">Requests</div><div class="v">${fmt(total)}</div><div class="s">last ${days} day${days === 1 ? "" : "s"}</div></div>
<div class="tile"><div class="l">Human page views</div><div class="v">${fmt(views)}</div><div class="s">bots and assets excluded</div></div>
<div class="tile"><div class="l">Bot share</div><div class="v">${share}%</div><div class="s">${share}% of 2xx from bots</div></div>
<div class="tile"><div class="l">Hosts</div><div class="v">${model.length}</div><div class="s">${model.filter((h) => h.pageviews).length} with human traffic</div></div>
</div>
${model.length ? `<div class="card"><p class="cap">Requests per day, all hosts</p>${bars(sum, window, "total requests per day", true)}</div>` : ""}`
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escapeHtml(config.title)}</title>
<style>
${CSS}
</style></head><body>
<div class="top"><h1>${escapeHtml(config.title)}</h1>
<p class="muted">${total} requests · last ${days} day${days === 1 ? "" : "s"}${host ? ` · ${escapeHtml(host)}` : ""} · generated ${escapeHtml(generated)} · cached up to 5 min</p></div>
<nav class="bar" aria-label="filters"><div class="seg" aria-label="days">${dayLinks}</div><div class="chips" aria-label="hosts">${hostLinks}</div></nav>
${model.partial ? `<p class="note">Breakdowns are partial: the detail query hit its ${OK_LIMIT}-group cap, so human counts are a lower bound.</p>` : ""}
${model.length ? `${tiles}
${model.map((h) => hostSection(h, window, services)).join("\n")}` : `<p class="empty muted">No data in this window.</p>`}
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
