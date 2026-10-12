// spor: pure logic for the dashboard, API and CLI: config, SQL, classification, rendering, auth.
// Import-free so node:test loads it directly. Every blob in the dataset is
// attacker-written (paths, user agents, referers), so all of it is escaped.

// Instance config comes from the Worker var SPOR (wrangler.jsonc "vars": { "SPOR": {...} }),
// so this file holds no hostnames. See wrangler.example.jsonc.
export function loadConfig(raw) {
  const c = typeof raw === "string" ? JSON.parse(raw) : (raw ?? {})
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v)
  if (!isObject(c)) throw new Error("spor: config must be an object")
  if (c.services !== undefined && !isObject(c.services)) throw new Error("spor: config.services must be an object of host -> description")
  if (c.proxyHosts !== undefined && !Array.isArray(c.proxyHosts)) throw new Error("spor: config.proxyHosts must be an array")
  if (c.local !== undefined && !Array.isArray(c.local)) throw new Error("spor: config.local must be an array")
  if (c.recordIp !== undefined && typeof c.recordIp !== "boolean") throw new Error("spor: config.recordIp must be true or false")
  for (const k of ["title", "dataset", "llm"]) {
    if (c[k] !== undefined && typeof c[k] !== "string") throw new Error(`spor: config.${k} must be a string`)
  }
  const dataset = String(c.dataset || "spor_analytics")
  if (!/^[A-Za-z0-9_]+$/.test(dataset)) throw new Error("spor: config.dataset must match [A-Za-z0-9_]+")
  const services = Object.fromEntries(Object.entries(c.services || {}).map(([h, d]) => [String(h).toLowerCase(), String(d)]))
  // hosts reach SQL as literals (index1 = '<host>'), so only hostname characters are allowed
  for (const h of Object.keys(services)) {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(h)) throw new Error(`spor: config.services has an invalid host name: ${JSON.stringify(h)}`)
  }
  // hosts the self-hosted backend counts itself (nginx log or /api/ingest); each must be a configured host
  const local = (c.local || []).map((h) => String(h).toLowerCase())
  for (const h of local) {
    if (!(h in services)) throw new Error(`spor: config.local lists ${JSON.stringify(h)}, which is not in config.services`)
  }
  return {
    title: String(c.title || "spor"),
    dataset,
    services,
    hosts: Object.keys(services),
    proxyHosts: new Set((c.proxyHosts || []).map((h) => String(h).toLowerCase())),
    local: new Set(local),
    // the self-hosted backend stores client IPs only when this is true (the tap has RECORD_IP)
    recordIp: c.recordIp === true
  }
}

export const DEFAULT_DAYS = 7
export const MAX_DAYS = 31
export const OK_LIMIT = 2000
const TOP = 10

export const LIMITS = { geo: 500, networks: 500, agents: 1000, ips: 200 }
// Analytics Engine keeps 92 days; a day filter may reach that far back
export const RETENTION_DAYS = 92

const ASSET = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|map|json|webmanifest|txt|md)$/i

// ---- agent classes -----------------------------------------------------------------------
// First match wins, so the narrower AI classes come first: Claude-User and Claude-SearchBot
// carry "+claudebot@anthropic.com" in their user agents. `ua` holds substrings of the user agent, `asorg` substrings of the AS
// organisation, matched case-insensitively (ASCII). `cat` holds Cloudflare verifiedBotCategory
// values. One table drives classOf() in JavaScript and classSql() in Analytics Engine SQL and
// SQLite, so a filter, a table and a tile always agree, and old rows reclassify when it changes.
// AI agents after github.com/ai-robots-txt/ai.robots.txt (training, search, user-triggered fetch).
export const CLASSES = [
  { id: "ai-user", label: "AI assistants fetching for a person", ua: ["ChatGPT-User", "Claude-User", "Perplexity-User", "MistralAI-User", "meta-externalfetcher", "cohere-ai", "Gemini-Deep-Research", "Google-NotebookLM", "DuckAssistant"], cat: ["AI Assistant"] },
  { id: "ai-search", label: "AI search crawlers", ua: ["OAI-SearchBot", "Claude-SearchBot", "PerplexityBot", "YouBot", "DuckAssistBot", "Amazonbot", "PhindBot", "Bravebot", "Kimi-SearchBot", "Meta-WebIndexer", "OAI-AdsBot"], cat: ["AI Search"] },
  { id: "ai-training", label: "AI training crawlers", ua: ["GPTBot", "ClaudeBot/", "anthropic-ai", "CCBot", "Bytespider", "meta-externalagent", "Diffbot", "Applebot-Extended", "cohere-training-data-crawler", "AI2Bot", "ImagesiftBot", "Timpibot", "omgili", "PanguBot", "Kangaroo Bot", "Google-Extended", "ChatGLM-Spider", "DeepSeekBot", "Qwenbot", "YiBot", "KimiBot", "MoonshotBot", "GrokBot"], cat: ["AI Crawler"] },
  { id: "search", label: "search engines", ua: ["Googlebot", "Google-InspectionTool", "Storebot-Google", "bingbot", "Applebot", "DuckDuckBot", "YandexBot", "Baiduspider", "PetalBot", "SeznamBot", "Qwantbot", "MojeekBot", "Yeti/"], cat: ["Search Engine Crawler", "Search Engine Optimization"] },
  { id: "preview", label: "link previews", ua: ["facebookexternalhit", "Slackbot", "Discordbot", "Twitterbot", "LinkedInBot", "WhatsApp", "TelegramBot", "SkypeUriPreview", "redditbot", "Embedly", "Iframely", "Mastodon", "Bluesky", "preview"], cat: ["Page Preview"] },
  { id: "monitor", label: "uptime monitors", ua: ["uptime", "monitor", "Pingdom", "StatusCake", "Better Stack", "updown.io", "Site24x7", "healthcheck"], cat: ["Monitoring & Analytics"] },
  { id: "scanner", label: "vulnerability scanners", ua: ["zgrab", "masscan", "nuclei", "censys", "shodan", "expanse", "palo alto", "internet-measurement", "scanner", "l9explore", "l9tcpid", "Nmap", "sqlmap", "Nikto", "WPScan", "leakix", "fuzz"], cat: ["Security"] },
  { id: "tool", label: "scripts and HTTP libraries", ua: ["curl/", "Wget", "python", "httpx", "Go-http-client", "Java/", "okhttp", "Scrapy", "Headless", "node-fetch", "axios/", "libwww", "aiohttp", "undici", "PostmanRuntime", "Apache-HttpClient"] },
  { id: "bot", label: "other bots", ua: ["bot", "crawl", "spider", "slurp"], anyCat: true, emptyUa: true },
  // a browser user agent from a hosting network is almost always automation. No Cloudflare,
  // Akamai or Fastly: those carry iCloud Private Relay and WARP users
  { id: "cloud", label: "browsers on cloud networks", asorg: ["amazon", "google", "microsoft", "digitalocean", "hetzner", "ovh", "linode", "alibaba", "tencent", "oracle", "vultr", "choopa", "contabo", "scaleway", "leaseweb", "m247", "hostinger", "datacamp", "upcloud", "netcup", "huawei cloud"] }
]
export const CLASS_IDS = [...CLASSES.map((c) => c.id), "human"]
export const classLabel = (id) => CLASSES.find((c) => c.id === id)?.label ?? "people"

// ASCII-only lowercasing, the same as SQL lower() in both stores
const lowerAscii = (s) => String(s || "").replace(/[A-Z]/g, (c) => c.toLowerCase())
// lowercase copies of the tokens, made once: classOf runs for every row of every report
const LOWER = new Map(CLASSES.map((c) => [c, { ua: (c.ua || []).map(lowerAscii), asorg: (c.asorg || []).map(lowerAscii) }]))
for (const c of CLASSES) {
  for (const t of [...(c.ua || []), ...(c.asorg || []), ...(c.cat || [])]) {
    // tokens become SQL literals and LIKE patterns: no quotes, backslashes or wildcards
    if (!/^[A-Za-z0-9 ./&-]+$/.test(t)) throw new Error(`spor: bad class token ${t}`)
  }
}

// row: { ua, bot, asorg } -> a CLASS_IDS entry
export function classOf(row) {
  const ua = row.ua || ""
  const bot = row.bot || ""
  const u = lowerAscii(ua)
  const o = lowerAscii(row.asorg)
  for (const c of CLASSES) {
    const low = LOWER.get(c)
    if ((c.emptyUa && !ua) || (c.anyCat && bot) || c.cat?.includes(bot) || low.ua.some((t) => u.includes(t)) || low.asorg.some((t) => o.includes(t))) return c.id
  }
  return "human"
}

// classOf with a memo, for one build(): rows repeat the same user agents many times
function classifier() {
  const memo = new Map()
  return (row) => {
    const key = `${row.ua || ""}\u0000${row.bot || ""}\u0000${row.asorg || ""}`
    let id = memo.get(key)
    if (id === undefined) memo.set(key, (id = classOf(row)))
    return id
  }
}

// The SQL twin of matches(), over column names that differ per store
function matchSql(c, col) {
  const parts = []
  if (c.emptyUa) parts.push(`${col.ua} = ''`)
  if (c.anyCat) parts.push(`${col.bot} != ''`)
  for (const t of c.cat || []) parts.push(`${col.bot} = '${t}'`)
  for (const t of c.ua || []) parts.push(`lower(${col.ua}) LIKE '%${lowerAscii(t)}%'`)
  for (const t of c.asorg || []) parts.push(`lower(${col.asorg}) LIKE '%${t}%'`)
  return `(${parts.join(" OR ")})`
}

// A WHERE fragment that is true exactly when classOf(row) === id
export function classSql(id, col) {
  const i = CLASSES.findIndex((c) => c.id === id)
  const earlier = (i < 0 ? CLASSES : CLASSES.slice(0, i)).map((c) => matchSql(c, col))
  const not = earlier.length ? `NOT (${earlier.join(" OR ")})` : ""
  if (i < 0) return `(${not})`
  return `(${matchSql(CLASSES[i], col)}${not ? ` AND ${not}` : ""})`
}

export const AE_COLUMNS = { host: "index1", path: "blob1", referer: "blob2", ua: "blob3", country: "blob4", status: "blob5", bot: "blob6", origin: "blob7", method: "blob8", city: "blob9", region: "blob10", asn: "blob11", asorg: "blob12", visitor: "blob13", ip: "blob14" }
const PROBE = /wp-|\.php|\.env|\/\.git|xmlrpc|\/admin|\/cgi-bin|\/vendor\/|\/\.well-known\/security/i
// a proxy target is /<hostname>; scanners' /wp.php or /.well-known only look like one
const TARGET = /^\/[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i

// The Worker refuses to run without a config (the CLI keeps loadConfig's lenient defaults)
export function requireConfig(raw) {
  if (raw === undefined || raw === null || raw === "") throw new Error("spor: vars.SPOR is missing from wrangler.jsonc")
  return loadConfig(raw)
}

// ---- input -------------------------------------------------------------------------------

export function clampDays(value) {
  if (typeof value !== "string" || !/^\d{1,3}$/.test(value)) return DEFAULT_DAYS
  return Math.min(MAX_DAYS, Math.max(1, Number(value)))
}

export function validHost(value, config) {
  return config.hosts.includes(value) ? value : null
}

// The window is whole UTC calendar days ending today, the same days the charts show
export function windowStart(days, now = Date.now()) {
  const today = Date.parse(new Date(now).toISOString().slice(0, 10) + "T00:00:00Z")
  return new Date(today - (clampDays(String(days)) - 1) * 86400000).toISOString().slice(0, 19).replace("T", " ")
}

// ---- filters ----------------------------------------------------------------------------
// Drill-down filters from the query string. Analytics Engine SQL has no bound parameters, so every
// value that reaches it matches a pattern without quotes, backslashes or whitespace; anything
// else is dropped, never escaped. SQLite gets the same values as bound parameters.
export const FILTER_KEYS = ["day", "country", "asn", "class", "path", "ip"]

function v4hex(ip) {
  const parts = ip.split(".")
  if (parts.length !== 4) return null
  let out = ""
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null
    out += Number(p).toString(16).padStart(2, "0")
  }
  return out
}

// An IPv4 or IPv6 address as 32 hex digits, IPv4 mapped into ::ffff:0:0/96, so ranges of both
// families sort and compare as plain strings. null for anything that isn't an address.
export function ipToHex(value) {
  let ip = String(value ?? "").trim().toLowerCase()
  if (!ip.includes(":")) {
    const h = v4hex(ip)
    return h && `00000000000000000000ffff${h}`
  }
  if (!/^[0-9a-f:.]+$/.test(ip)) return null
  const last = ip.slice(ip.lastIndexOf(":") + 1)
  if (last.includes(".")) {
    const h = v4hex(last)
    if (!h) return null
    ip = `${ip.slice(0, ip.length - last.length)}${h.slice(0, 4)}:${h.slice(4)}`
  }
  const halves = ip.split("::")
  if (halves.length > 2) return null
  const groups = (s) => (s === "" ? [] : s.split(":"))
  const left = groups(halves[0])
  const right = halves.length === 2 ? groups(halves[1]) : []
  const missing = 8 - left.length - right.length
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null
  const all = [...left, ...new Array(halves.length === 2 ? missing : 0).fill("0"), ...right]
  if (all.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return all.map((g) => g.padStart(4, "0")).join("")
}

export function parseFilters(params, now = Date.now()) {
  const get = (k) => {
    const v = params?.get?.(k)
    return typeof v === "string" ? v : ""
  }
  const out = {}
  const day = get("day")
  if (/^\d{4}-\d{2}-\d{2}$/.test(day)) {
    const t = Date.parse(`${day}T00:00:00Z`)
    const today = Date.parse(new Date(now).toISOString().slice(0, 10) + "T00:00:00Z")
    if (Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === day && t <= today && t > today - RETENTION_DAYS * 86400000) out.day = day
  }
  if (/^[A-Z0-9]{2}$/.test(get("country"))) out.country = get("country")
  if (/^\d{1,10}$/.test(get("asn"))) out.asn = get("asn")
  if (CLASS_IDS.includes(get("class"))) out.class = get("class")
  // printable ASCII without ' and \ (the tap cuts paths at 64 characters)
  if (/^\/[\x21-\x26\x28-\x5b\x5d-\x7e]{0,63}$/.test(get("path"))) out.path = get("path")
  // an address ipToHex can read (it rejects malformed IPv6 such as 1::2::3), at most 45 characters
  const ip = get("ip").toLowerCase()
  if (ip.length <= 45 && ipToHex(ip)) out.ip = ip
  return out
}

// The window: whole UTC days ending today, or the one day a day filter names, by the hour
export function span(days, filters = {}, now = Date.now()) {
  const sql = (t) => new Date(t).toISOString().slice(0, 19).replace("T", " ")
  if (filters.day) {
    const from = Date.parse(`${filters.day}T00:00:00Z`)
    return { from: sql(from), to: sql(from + 86400000), fromSeconds: from / 1000, toSeconds: from / 1000 + 86400, hourly: true }
  }
  const from = Date.parse(windowStart(days, now).replace(" ", "T") + "Z")
  const to = Date.parse(new Date(now).toISOString().slice(0, 10) + "T00:00:00Z") + 86400000
  return { from: sql(from), to: sql(to), fromSeconds: from / 1000, toSeconds: to / 1000, hourly: clampDays(String(days)) === 1 }
}

// filters -> SQL conditions over `col`, with `lit` turning a validated value into SQL (a quoted
// literal for AE, a ? placeholder for SQLite)
export function filterSql(filters, col, lit) {
  const parts = []
  for (const k of ["country", "asn", "path", "ip"]) if (filters[k]) parts.push(`${col[k]} = ${lit(filters[k])}`)
  if (filters.class) parts.push(classSql(filters.class, col))
  return parts.map((p) => ` AND ${p}`).join("")
}

// The capped result sets build() expects, as Analytics Engine SQL. days, host, dataset and every
// filter are validated before they get here (see parseFilters). The capped queries break ties on
// the group columns, so the cut is deterministic and the self-hosted store (src/store.js) cuts at
// the same rows. Keep the two in step.
export function queries(days, host, config, now = Date.now(), filters = {}) {
  const d = clampDays(String(days))
  const h = validHost(host, config)
  const f = parseFilters(new URLSearchParams(Object.entries(filters).filter(([, v]) => typeof v === "string")), now)
  const w = span(d, f, now)
  const c = AE_COLUMNS
  const from = `FROM ${config.dataset} WHERE timestamp >= toDateTime('${w.from}') AND timestamp < toDateTime('${w.to}')` + (h ? ` AND index1 = '${h}'` : "") + filterSql(f, c, (v) => `'${v}'`)
  const n = "SUM(_sample_interval) AS n"
  const ok = "blob5 >= '200' AND blob5 < '300'"
  // tables of people (cities, visitors) follow a class filter when there is one
  const people = f.class ? "" : ` AND ${classSql("human", c)}`
  const human = classSql("human", c)
  return {
    totals: `SELECT index1 AS host, blob5 AS status, ${n} ${from} GROUP BY host, status FORMAT JSON`,
    daily: `SELECT toStartOfInterval(timestamp, INTERVAL '1' ${w.hourly ? "HOUR" : "DAY"}) AS day, index1 AS host, ${n} ${from} GROUP BY day, host ORDER BY day FORMAT JSON`,
    ok: `SELECT index1 AS host, blob1 AS path, blob2 AS referer, blob3 AS ua, blob4 AS country, blob6 AS bot, blob8 AS method, blob12 AS asorg, ${n} ${from} AND ${ok} AND blob3 != '' GROUP BY host, path, referer, ua, country, bot, method, asorg ORDER BY n DESC, host, path, referer, ua, country, bot, method, asorg LIMIT ${OK_LIMIT} FORMAT JSON`,
    paths: `SELECT index1 AS host, blob1 AS path, blob5 AS status, ${n} ${from} GROUP BY host, path, status ORDER BY n DESC, host, path, status LIMIT 500 FORMAT JSON`,
    origins: `SELECT index1 AS host, blob7 AS origin, ${n} ${from} AND blob7 != '' GROUP BY host, origin ORDER BY n DESC, host, origin LIMIT 50 FORMAT JSON`,
    geo: `SELECT index1 AS host, blob4 AS country, blob10 AS region, blob9 AS city, ${n} ${from} AND ${ok} AND blob9 != ''${people} GROUP BY host, country, region, city ORDER BY n DESC, host, country, region, city LIMIT ${LIMITS.geo} FORMAT JSON`,
    networks: `SELECT index1 AS host, blob11 AS asn, blob12 AS asorg, ${n} ${from} AND blob11 != '' GROUP BY host, asn, asorg ORDER BY n DESC, host, asn, asorg LIMIT ${LIMITS.networks} FORMAT JSON`,
    agents: `SELECT index1 AS host, blob3 AS ua, blob6 AS bot, blob12 AS asorg, ${n} ${from} AND NOT ${human} GROUP BY host, ua, bot, asorg ORDER BY n DESC, host, ua, bot, asorg LIMIT ${LIMITS.agents} FORMAT JSON`,
    visitors: `SELECT index1 AS host, toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day, count(DISTINCT blob13) AS v ${from} AND blob13 != ''${people} GROUP BY host, day FORMAT JSON`,
    ips: `SELECT index1 AS host, blob14 AS ip, blob12 AS asorg, blob4 AS country, ${n} ${from} AND blob14 != '' GROUP BY host, ip, asorg, country ORDER BY n DESC, host, ip, asorg, country LIMIT ${LIMITS.ips} FORMAT JSON`,
    // toDayOfWeek: 1 = Monday ... 7 = Sunday, UTC
    heat: `SELECT toDayOfWeek(timestamp) AS dow, toHour(timestamp) AS hr, ${n} ${from} GROUP BY dow, hr FORMAT JSON`
  }
}

// ---- classification ----------------------------------------------------------------------

export function isBot(row) {
  return classOf(row) !== "human"
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

// The agent behind a non-human row, for the bots card: the class token it matched, else the first
// bot-like product token, the Cloudflare category, or the network for "cloud"
export function agentName(row, id = classOf(row)) {
  const c = CLASSES.find((x) => x.id === id)
  if (!c || id === "human") return ""
  if (id === "cloud") return row.asorg || "cloud"
  const u = lowerAscii(row.ua)
  // the generic class's tokens (bot, crawl) are fragments, not names
  const token = id === "bot" ? null : c.ua?.find((t) => u.includes(lowerAscii(t)) && t.length > 4)
  if (token) return token.replace(/\/$/, "")
  if (!row.ua) return row.bot || "no user agent"
  const product = /[A-Za-z][\w.-]*(bot|crawler|spider|scanner)[\w.-]*/i.exec(row.ua)?.[0]
  return product || row.bot || row.ua.slice(0, 40)
}

// filtered: a class filter is on, so every detail row already belongs to the class asked for and
// the page tables show its fetches, not only people's
export function build({ totals = [], daily = [], ok = [], paths = [], origins = [], geo = [], networks = [], agents = [], visitors = [], ips = [], heat = [] }, config, { hourly = false, filtered = false } = {}) {
  const classify = classifier()
  const hosts = new Map()
  const get = (name) => {
    if (!hosts.has(name)) {
      hosts.set(name, {
        host: name, requests: 0, ok2xx: 0, humans2xx: 0, pageviews: 0, bots: 0, visitors: 0, status: new Map(), daily: new Map(), pages: new Map(),
        referers: new Map(), countries: new Map(), browsers: new Map(), probes: new Map(), targets: new Map(), origins: new Map(),
        cities: new Map(), networks: new Map(), classes: new Map(), agents: new Map(), ips: new Map(), names: new Map()
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
  // a day key, or "YYYY-MM-DD HH" when the window is a single day
  for (const r of daily) add(get(r.host).daily, String(r.day).slice(0, hourly ? 13 : 10), num(r.n))
  for (const r of ok) {
    const h = get(r.host)
    const n = num(r.n)
    if (classify(r) !== "human") {
      if (!filtered) continue
    } else h.humans2xx += n
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
  for (const r of geo) add(get(r.host).cities, [r.city, r.region, r.country].filter(Boolean).join(", "), num(r.n))
  for (const r of networks) {
    const h = get(r.host)
    add(h.networks, String(r.asn), num(r.n))
    h.names.set(`as:${r.asn}`, r.asorg || "")
  }
  for (const r of agents) {
    const h = get(r.host)
    const n = num(r.n)
    const id = classify(r)
    add(h.classes, id, n)
    add(h.agents, `${id}\t${agentName(r, id)}`, n)
  }
  for (const r of visitors) get(r.host).visitors += num(r.v)
  for (const r of ips) {
    const h = get(r.host)
    add(h.ips, r.ip, num(r.n))
    h.names.set(`ip:${r.ip}`, [r.country, r.asorg].filter(Boolean).join(" · "))
  }

  // bots = every 2xx that wasn't a human row; empty-UA rows never reach the detail query
  for (const h of hosts.values()) h.bots = Math.max(0, h.ok2xx - h.humans2xx)
  const model = [...hosts.values()].sort((a, b) => b.requests - a.requests)
  // the detail query is capped: if it came back full, human counts are a lower bound
  model.partial = ok.length >= OK_LIMIT
  model.hourly = hourly
  // requests by weekday (1 = Monday) and UTC hour, all hosts in the filter
  model.heat = Array.from({ length: 7 }, () => new Array(24).fill(0))
  for (const r of heat) {
    const d = num(r.dow)
    const hr = num(r.hr)
    if (d >= 1 && d <= 7 && hr >= 0 && hr < 24) model.heat[d - 1][hr] += num(r.n)
  }
  return model
}

// The model as plain JSON (Maps become [key, count] lists, top first), for /api/report and the CLI
export function toJSON(model, config, { days, host, filters = {} } = {}) {
  const top = (map) => [...map.entries()].sort((a, b) => b[1] - a[1])
  return {
    days, host: host || null, filters, partial: Boolean(model.partial), heat: model.heat,
    hosts: model.map((h) => ({
      host: h.host, description: config.services[h.host] || null,
      requests: h.requests, ok2xx: h.ok2xx, pageviews: h.pageviews, bots: h.bots, visitors: h.visitors,
      status: top(h.status), daily: [...h.daily.entries()].sort(), pages: top(h.pages), referers: top(h.referers),
      countries: top(h.countries), browsers: top(h.browsers), probes: top(h.probes), targets: top(h.targets), origins: top(h.origins),
      cities: top(h.cities), networks: top(h.networks).map(([asn, n]) => [asn, h.names.get(`as:${asn}`) || "", n]),
      classes: top(h.classes), agents: top(h.agents).map(([k, n]) => [k.slice(0, k.indexOf("\t")), k.slice(k.indexOf("\t") + 1), n]),
      ips: top(h.ips).map(([ip, n]) => [ip, h.names.get(`ip:${ip}`) || "", n])
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

// A top-N table; every row carries an inline bar proportional to the largest row. label(key)
// names a row, link(key) returns an already-escaped href that drills down into it, or null.
function table(title, map, { label = (k) => k, link = () => null } = {}) {
  if (!map.size) return ""
  const rows = top(map)
  const max = Math.max(1, rows[0][1])
  const body = rows.map(([k, v]) => {
    const text = escapeHtml(label(k))
    const href = link(k)
    return `<tr><td><div class="cell"><i style="width:${Math.max(1, Math.round((v / max) * 100))}%"></i><span>${href ? `<a href="${href}">${text}</a>` : text}</span></div></td><td class="n">${v}</td></tr>`
  }).join("")
  return `<table><caption>${escapeHtml(title)}</caption>${body}</table>`
}

// ?days=..&host=..&<filters>, with `change` applied (null drops a key), escaped for an attribute
function hrefFor(state, change = {}) {
  const next = { ...state, ...change }
  const parts = [`days=${next.days}`]
  if (next.host) parts.push(`host=${encodeURIComponent(next.host)}`)
  for (const k of FILTER_KEYS) if (next[k]) parts.push(`${k}=${encodeURIComponent(next[k])}`)
  return `?${parts.join("&amp;")}`
}

// a drill-down link only for a value the filter would accept
function filterLink(state, key, value) {
  const f = parseFilters(new URLSearchParams({ [key]: value }))
  return f[key] === value || (key === "ip" && f.ip === String(value).toLowerCase()) ? hrefFor(state, { [key]: value }) : null
}

function windowDays(days, today) {
  const end = Date.parse(`${today}T00:00:00Z`)
  return Array.from({ length: days }, (_, i) => new Date(end - (days - 1 - i) * 86400000).toISOString().slice(0, 10))
}

const WIDTH = 200
// Zero-filled per-day bars as inline SVG; one <rect> (with a hover <title>) per day in the window
// Hourly windows have "YYYY-MM-DD HH" keys; dayLink(day), when given, makes each day bar a link.
function bars(daily, window, label, tall = false, dayLink = null) {
  if (!daily.size) return ""
  const hourly = window[0].length > 10
  const unit = hourly ? "hour" : "day"
  const series = window.map((day) => [day, daily.get(day) || 0])
  const max = Math.max(1, ...series.map(([, v]) => v))
  const height = 40
  const step = WIDTH / series.length
  const bw = Math.min(12, Math.max(1, +(step * 0.6).toFixed(1)))
  const rects = series.map(([day, v], i) => {
    const h = v ? Math.max(2, Math.round((v / max) * (height - 2))) : 1
    const rect = `<rect x="${+(i * step + (step - bw) / 2).toFixed(1)}" y="${height - h}" width="${bw}" height="${h}"${v ? "" : ` class="z"`}><title>${escapeHtml(hourly ? `${day}:00` : day)}: ${v}</title></rect>`
    return dayLink && v && !hourly ? `<a href="${dayLink(day)}">${rect}</a>` : rect
  }).join("")
  const first = hourly ? `${window[0].slice(5)}:00` : window[0].slice(5)
  const last = hourly ? `${window[window.length - 1].slice(11)}:00` : window[window.length - 1].slice(5)
  return `<svg class="spark${tall ? " tall" : ""}" viewBox="0 0 ${WIDTH} ${height}" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(label)}: ${max} peak per ${unit}, ${escapeHtml(window[0])} to ${escapeHtml(window[window.length - 1])}">${rects}</svg>
<div class="axis"><span>${escapeHtml(first)}</span><span>peak ${max}/${unit}</span><span>${escapeHtml(last)}</span></div>`
}

const DOW = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
// Requests by weekday and UTC hour: one cell per hour, its opacity proportional to the busiest
function heatmap(heat) {
  const max = Math.max(0, ...heat.flat())
  if (!max) return ""
  const cells = heat.map((row, d) => row.map((v, h) => `<rect x="${24 + h * 10}" y="${d * 10}" width="9" height="9" style="opacity:${v ? (0.15 + 0.85 * v / max).toFixed(2) : 0.06}"><title>${DOW[d]} ${String(h).padStart(2, "0")}:00 UTC: ${v}</title></rect>`).join("")).join("")
  const labels = DOW.map((d, i) => `<text x="0" y="${i * 10 + 8}">${d}</text>`).join("")
  const hours = [0, 6, 12, 18, 23].map((h) => `<text x="${24 + h * 10}" y="80">${String(h).padStart(2, "0")}</text>`).join("")
  return `<svg class="heat" viewBox="0 0 264 82" role="img" aria-label="requests by weekday and hour, UTC, busiest ${max}">${labels}${cells}${hours}</svg>`
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

// when the detail query is capped, humans are a lower bound, so bots (2xx - humans) are an upper bound
const shareText = (share, capped) => (capped ? `≤${share}%` : `${share}%`)

function hostSection(h, window, services, capped, state) {
  const share = h.ok2xx ? Math.round((h.bots / h.ok2xx) * 100) : 0
  const desc = services[h.host]
  const here = { ...state, host: h.host }
  const by = (key) => ({ link: (k) => filterLink(here, key, k) })
  const agents = new Map([...h.agents].map(([k, n]) => [k, n]))
  return `<section class="card${h.pageviews ? "" : " quiet"}">
<header><h2>${escapeHtml(h.host)}${desc ? ` <span class="desc">${escapeHtml(desc)}</span>` : ""}</h2></header>
<p class="summary"><b>${fmt(h.requests)}</b> requests · <b>${fmt(h.pageviews)}</b> human page views${h.visitors ? ` · <b>${fmt(h.visitors)}</b> unique visitors` : ""} · ${shareText(share, capped)} of 2xx from bots${capped ? " (upper bound)" : ""}</p>
${bars(h.daily, window, `${h.host} requests`, false, (day) => hrefFor(here, { day }))}
${statusMix(h.status)}
<div class="grid">
${table("pages", h.pages, by("path"))}${table("referers", h.referers)}${table("countries", h.countries, by("country"))}${table("cities", h.cities)}${table("browsers", h.browsers)}${table("networks", h.networks, { label: (asn) => `AS${asn} ${h.names.get(`as:${asn}`) || ""}`.trim(), ...by("asn") })}${table("bots and AI", h.classes, { label: classLabel, ...by("class") })}${table("agents", agents, { label: (k) => k.slice(k.indexOf("\t") + 1), link: (k) => filterLink(here, "class", k.slice(0, k.indexOf("\t"))) })}${table("IP addresses", h.ips, { label: (ip) => `${ip} ${h.names.get(`ip:${ip}`) || ""}`.trim(), ...by("ip") })}${table("404s and probes", h.probes, by("path"))}${table("proxy targets", h.targets)}${table("proxy callers (Origin)", h.origins)}
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
.chips.on a{border-color:var(--accent);color:var(--fg)}
.heat{display:block;width:100%;max-width:528px;margin-top:12px;fill:var(--accent);font-size:7px}.heat text{fill:var(--muted)}
.cell a{color:inherit}.cell a:hover{color:var(--accent)}
.spark a rect{cursor:pointer}
.foot{font-size:12px;margin-top:24px}
@media (max-width:520px){body{padding:16px 12px 32px}.tile .v{font-size:24px}.card{padding:12px}}`

// credit: an attribution line the backend owes (the self-hosted server's DB-IP data is CC BY 4.0)
export function render(model, { days, host, filters = {}, generated, config, cache = "cached up to 5 min", credit = "", today = new Date().toISOString().slice(0, 10) }) {
  const services = config.services
  const state = { days, host, ...filters }
  // one day, by the hour, when the window is a day; whole days otherwise
  const window = filters.day || days === 1
    ? Array.from({ length: 24 }, (_, h) => `${filters.day || today} ${String(h).padStart(2, "0")}`)
    : windowDays(days, today)
  const dayLinks = [1, 7, 31].map((d) => d === days && !filters.day ? `<b aria-current="true">${d}d</b>` : `<a href="${hrefFor(state, { days: d, day: null })}">${d}d</a>`).join("")
  const hostLinks = [host ? `<a href="${hrefFor(state, { host: null })}">all</a>` : `<b aria-current="true">all</b>`, ...model.map((h) => `<a href="${hrefFor(state, { host: h.host })}"${services[h.host] ? ` title="${escapeHtml(services[h.host])}"` : ""}>${escapeHtml(h.host)}</a>`)].join("")
  const named = { class: classLabel }
  const active = FILTER_KEYS.filter((k) => filters[k]).map((k) => `<a href="${hrefFor(state, { [k]: null })}" title="remove this filter">${escapeHtml(k)}: ${escapeHtml(named[k] ? named[k](filters[k]) : filters[k])} ×</a>`).join("")
  const total = model.reduce((s, h) => s + h.requests, 0)
  const views = model.reduce((s, h) => s + h.pageviews, 0)
  const visitors = model.reduce((s, h) => s + h.visitors, 0)
  const ai = model.reduce((s, h) => s + [...h.classes].filter(([id]) => id.startsWith("ai-")).reduce((t, [, n]) => t + n, 0), 0)
  const ok = model.reduce((s, h) => s + h.ok2xx, 0)
  const bots = model.reduce((s, h) => s + h.bots, 0)
  const share = ok ? Math.round((bots / ok) * 100) : 0
  const span = filters.day ? escapeHtml(filters.day) : `last ${days} day${days === 1 ? "" : "s"}`
  const sum = new Map()
  for (const h of model) for (const [d, n] of h.daily) sum.set(d, (sum.get(d) || 0) + n)
  const tiles = `<div class="tiles">
<div class="tile"><div class="l">Requests</div><div class="v">${fmt(total)}</div><div class="s">${span}</div></div>
${filters.class && filters.class !== "human"
    ? `<div class="tile"><div class="l">Page views</div><div class="v">${fmt(views)}</div><div class="s">by ${escapeHtml(classLabel(filters.class))}</div></div>`
    : `<div class="tile"><div class="l">Human page views</div><div class="v">${fmt(views)}</div><div class="s">bots and assets excluded</div></div>`}
<div class="tile"><div class="l">Unique visitors</div><div class="v">${fmt(visitors)}</div><div class="s">people, counted per day</div></div>
<div class="tile"><div class="l">Bot share</div><div class="v">${shareText(share, model.partial)}</div><div class="s">${model.partial ? "upper bound: the detail query hit its cap" : `${share}% of 2xx from bots`}</div></div>
<div class="tile"><div class="l">AI requests</div><div class="v">${fmt(ai)}</div><div class="s"><a href="${hrefFor(state, { class: "ai-user" })}">assistants</a> · <a href="${hrefFor(state, { class: "ai-search" })}">search</a> · <a href="${hrefFor(state, { class: "ai-training" })}">training</a></div></div>
<div class="tile"><div class="l">Hosts</div><div class="v">${model.length}</div><div class="s">${model.filter((h) => h.pageviews).length} with human traffic</div></div>
</div>
${model.length ? `<div class="card"><p class="cap">Requests per ${window[0].length > 10 ? "hour" : "day"}, all hosts</p>${bars(sum, window, "total requests", true, (day) => hrefFor(state, { day }))}${heatmap(model.heat || [])}</div>` : ""}`
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escapeHtml(config.title)}</title>
<style>
${CSS}
</style></head><body>
<div class="top"><h1>${escapeHtml(config.title)}</h1>
<p class="muted">${total} requests · ${span}${host ? ` · ${escapeHtml(host)}` : ""} · generated ${escapeHtml(generated)}${cache ? ` · ${escapeHtml(cache)}` : ""}</p></div>
<nav class="bar" aria-label="filters"><div class="seg" aria-label="days">${dayLinks}</div><div class="chips" aria-label="hosts">${hostLinks}</div>${active ? `<div class="chips on" aria-label="active filters">${active}</div>` : ""}</nav>
${model.partial ? `<p class="note">Breakdowns are partial: the detail query hit its ${OK_LIMIT}-group cap, so human counts are a lower bound.</p>` : ""}
${model.length ? `${tiles}
${model.map((h) => hostSection(h, window, services, model.partial, state)).join("\n")}` : `<p class="empty muted">No data in this window.</p>`}
${credit ? `<p class="muted foot">${credit}</p>` : ""}
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
