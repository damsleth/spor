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
  if (c.aliases !== undefined && !isObject(c.aliases)) throw new Error("spor: config.aliases must be an object of host -> service host")
  if (c.recordIp !== undefined && typeof c.recordIp !== "boolean") throw new Error("spor: config.recordIp must be true or false")
  for (const k of ["title", "dataset", "llm"]) {
    if (c[k] !== undefined && typeof c[k] !== "string") throw new Error(`spor: config.${k} must be a string`)
  }
  const dataset = String(c.dataset || "spor_analytics")
  if (!/^[A-Za-z0-9_]+$/.test(dataset)) throw new Error("spor: config.dataset must match [A-Za-z0-9_]+")
  const services = Object.fromEntries(Object.entries(c.services || {}).map(([h, d]) => [String(h).toLowerCase(), String(d)]))
  // hosts reach SQL as literals (index1 = '<host>'), so only hostname characters are allowed
  for (const h of Object.keys(services)) {
    if (!HOSTNAME.test(h)) throw new Error(`spor: config.services has an invalid host name: ${JSON.stringify(h)}`)
  }
  // aliases: other names of one service (www.example.com -> example.com), counted as that service
  const aliases = Object.fromEntries(Object.entries(c.aliases || {}).map(([a, s]) => [String(a).toLowerCase(), String(s).toLowerCase()]))
  for (const [a, s] of Object.entries(aliases)) {
    if (!HOSTNAME.test(a) || !HOSTNAME.test(s)) throw new Error(`spor: config.aliases has an invalid host name: ${JSON.stringify(a)} -> ${JSON.stringify(s)}`)
    if (a === s || s in aliases) throw new Error(`spor: config.aliases must point at a service, not at itself or another alias: ${a} -> ${s}`)
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
    aliases,
    // the self-hosted backend stores client IPs only when this is true (the tap has RECORD_IP)
    recordIp: c.recordIp === true
  }
}

const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/
export const MAX_HOSTS = 20

// A host as one name: lowercase, without the trailing dot of a fully qualified name ("example.com.")
export const normalizeHost = (h) => String(h || "").toLowerCase().replace(/\.$/, "")
// the service a host belongs to: itself, or the service its alias points at
export const serviceOf = (host, config) => config.aliases?.[normalizeHost(host)] || normalizeHost(host)

export const DEFAULT_DAYS = 7
export const MAX_DAYS = 31
export const OK_LIMIT = 2000
const TOP = 10

export const LIMITS = { geo: 500, networks: 500, agents: 1000, ips: 200, canaries: 200 }
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

export const AE_COLUMNS = { host: "index1", path: "blob1", referer: "blob2", ua: "blob3", country: "blob4", status: "blob5", bot: "blob6", origin: "blob7", method: "blob8", city: "blob9", region: "blob10", asn: "blob11", asorg: "blob12", visitor: "blob13", ip: "blob14", lat: "blob15", lon: "blob16", sink: "blob17", sinkctx: "blob18" }

// ---- sinkhole ------------------------------------------------------------------------------
// Paths scanners probe for secrets, most probed first in spor's own data (October 2026). The tap
// answers a match with bait (tap/sink.js) when the origin has nothing there. First match wins.
export const BAIT = [
  // /.env, /.env.local, /src/.env, /@fs/app/.env, /backup.env
  { kind: "env", test: /(^|\/)\.env(\.[\w-]+)?$|\/[\w.-]+\.env$/i },
  { kind: "git", test: /\/\.git\/(config|HEAD)$|\/\.git-credentials$/ },
  { kind: "aws", test: /\/\.aws\/credentials$|\/\.boto$|\/\.s3cfg$/ },
  { kind: "npm", test: /\/\.npmrc$/ },
  { kind: "docker", test: /\/Dockerfile$|\/docker-compose\.ya?ml$/i },
  { kind: "php", test: /\.php\d?$/i },
  { kind: "userfiles", test: /^\/userfiles\/?$/i }
]
export const baitKind = (path) => BAIT.find((b) => b.test.test(String(path || "")))?.kind || ""
export const BAIT_KINDS = BAIT.map((b) => b.kind)

// Who never gets bait: AI assistants fetching for a person, AI search and search engines, unless
// their operator says they don't follow robots.txt (ai.robots.txt, OpenAI's crawler docs).
export const SINK_EXEMPT = ["ai-user", "ai-search", "search"]
export const IGNORES_ROBOTS = ["Perplexity-User", "ChatGPT-User"]
export function sinkable(row) {
  if (!SINK_EXEMPT.includes(classOf(row))) return true
  const u = lowerAscii(row.ua)
  return IGNORES_ROBOTS.some((t) => u.includes(lowerAscii(t)))
}
const PROBE = /wp-|\.php|\.env|\/\.git|xmlrpc|\/admin|\/cgi-bin|\/vendor\/|\/\.well-known\/security|\/\.aws\/|\/\.boto|\/\.s3cfg|\/\.npmrc|\/Dockerfile|\/docker-compose|\/userfiles/i
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

// ?host=: one or more services or host names, comma-separated. A name ending in "!" means that
// name only, without the aliases of the service it names. Every name must look like a host name
// (so it is safe as a SQL literal); the rest are dropped. Returns "a,b!" or null for all hosts.
export function validHost(value, config) {
  if (typeof value !== "string") return null
  const items = value.split(",").map((item) => {
    // "*.example.com": a whole domain, every name under it and itself
    const domain = item.startsWith("*.")
    const exact = !domain && item.endsWith("!")
    const name = normalizeHost(domain ? item.slice(2) : exact ? item.slice(0, -1) : item)
    if (!(name.length <= 253 && HOSTNAME.test(name))) return null
    return domain ? `*.${name}` : `${name}${exact ? "!" : ""}`
  })
  const names = [...new Set(items.filter(Boolean))].slice(0, MAX_HOSTS)
  return names.length ? names.join(",") : null
}

// A host's domain, the one it is grouped under: its last two labels (blog.example.com ->
// example.com). ponytail: a two-label public suffix (example.co.uk) groups as co.uk; a public
// suffix list would fix that
export const domainOf = (host) => normalizeHost(host).split(".").slice(-2).join(".")

// Does a selected item cover a host: a domain ("*.d") every name under it and itself, else the
// names coveredHosts lists
export function covers(item, host, config) {
  const h = normalizeHost(host)
  if (item.startsWith("*.")) return h === item.slice(2) || h.endsWith(`.${item.slice(2)}`)
  return coveredHosts(item, config).includes(h)
}

// The host names one selected item covers: a service brings its aliases, "name!" only itself;
// every name also matches its fully qualified form with a trailing dot, which some clients send
export function coveredHosts(item, config) {
  const exact = item.endsWith("!")
  const name = exact ? item.slice(0, -1) : item
  const names = [name, ...(exact ? [] : Object.entries(config.aliases || {}).filter(([, s]) => s === name).map(([a]) => a))]
  return names.flatMap((h) => [h, `${h}.`])
}

export function selectedHosts(host, config) {
  return host ? [...new Set(host.split(",").filter((item) => !item.startsWith("*.")).flatMap((item) => coveredHosts(item, config)))] : []
}

// the host condition for queries(): AE gets quoted literals, SQLite placeholders through lit. A
// domain is itself or anything ending in ".domain" (a validated host name has no quote, % or _)
export function hostSql(host, config, col, lit) {
  if (!host) return ""
  const parts = []
  const names = selectedHosts(host, config)
  if (names.length) parts.push(`${col} IN (${names.map(lit).join(", ")})`)
  for (const item of host.split(",").filter((i) => i.startsWith("*."))) {
    const d = item.slice(2)
    parts.push(`${col} = ${lit(d)}`, `${col} = ${lit(`${d}.`)}`, `${col} LIKE ${lit(`%.${d}`)}`, `${col} LIKE ${lit(`%.${d}.`)}`)
  }
  return parts.length ? ` AND (${parts.join(" OR ")})` : ""
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
export const FILTER_KEYS = ["view", "from", "to", "pick", "cal", "day", "country", "city", "asn", "class", "path", "ip"]
// the window and the calendar's state: carried in links, never shown as filter chips
const RANGE_KEYS = ["from", "to", "pick", "cal"]

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
  const today = Date.parse(new Date(now).toISOString().slice(0, 10) + "T00:00:00Z")
  // a real date, not after today and within AE's 92 days
  const date = (v) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return ""
    const t = Date.parse(`${v}T00:00:00Z`)
    return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === v && t <= today && t > today - RETENTION_DAYS * 86400000 ? v : ""
  }
  if (date(get("day"))) out.day = get("day")
  // a custom window, from and to inclusive (swapped if given backwards); from alone is a range
  // being picked
  const from = date(get("from"))
  const to = date(get("to"))
  if (from && to) [out.from, out.to] = from <= to ? [from, to] : [to, from]
  else if (from) out.from = from
  // the calendar: which end is being picked, and its first month
  if (["from", "to"].includes(get("pick"))) out.pick = get("pick")
  if (/^\d{4}-(0[1-9]|1[0-2])$/.test(get("cal"))) {
    const first = new Date(today - (RETENTION_DAYS - 1) * 86400000).toISOString().slice(0, 7)
    const last = new Date(today).toISOString().slice(0, 7)
    if (get("cal") >= first && get("cal") <= last) out.cal = get("cal")
  }
  if (/^[A-Z0-9]{2}$/.test(get("country"))) out.country = get("country")
  // a city name as Cloudflare or DB-IP writes it: letters in any script, digits, spaces and .,()-
  // (no quotes or backslashes, so it is safe as an AE literal; a city with an apostrophe can't be
  // picked). It names a place together with its country.
  if (/^[\p{L}\p{M}\p{N} .,()-]{1,64}$/u.test(get("city")) && get("city").trim() === get("city")) out.city = get("city")
  if (/^\d{1,10}$/.test(get("asn"))) out.asn = get("asn")
  if (CLASS_IDS.includes(get("class"))) out.class = get("class")
  // the sinkhole view: only bait, canary uses and /_internal/ challenges
  if (get("view") === "sink") out.view = "sink"
  // printable ASCII without ' and \ (the tap cuts paths at 64 characters)
  if (/^\/[\x21-\x26\x28-\x5b\x5d-\x7e]{0,63}$/.test(get("path"))) out.path = get("path")
  // an address ipToHex can read (it rejects malformed IPv6 such as 1::2::3), at most 45 characters
  const ip = get("ip").toLowerCase()
  if (ip.length <= 45 && ipToHex(ip)) out.ip = ip
  return out
}

// The window: whole UTC days ending today, or the one day a day filter names. step is the hours
// per point of the requests chart: 1 up to a week, 6 beyond (124 points for 31 days)
// how many days the window spans: a day filter one, a custom range its days, else days
export const spanDays = (days, filters = {}) => (filters.day ? 1 : filters.from && filters.to ? Math.round((Date.parse(filters.to) - Date.parse(filters.from)) / 86400000) + 1 : clampDays(String(days)))
// hours per point of the time charts: 1 up to a week, 6 up to a month, 24 beyond
export const stepHours = (days, filters = {}) => {
  const n = spanDays(days, filters)
  return n <= 7 ? 1 : n <= 31 ? 6 : 24
}
export function span(days, filters = {}, now = Date.now()) {
  const sql = (t) => new Date(t).toISOString().slice(0, 19).replace("T", " ")
  if (filters.day) {
    const from = Date.parse(`${filters.day}T00:00:00Z`)
    return { from: sql(from), to: sql(from + 86400000), fromSeconds: from / 1000, toSeconds: from / 1000 + 86400, hourly: true, step: 1 }
  }
  if (filters.from && filters.to) {
    const from = Date.parse(`${filters.from}T00:00:00Z`)
    const to = Date.parse(`${filters.to}T00:00:00Z`) + 86400000
    return { from: sql(from), to: sql(to), fromSeconds: from / 1000, toSeconds: to / 1000, hourly: filters.from === filters.to, step: stepHours(days, filters) }
  }
  const from = Date.parse(windowStart(days, now).replace(" ", "T") + "Z")
  const to = Date.parse(new Date(now).toISOString().slice(0, 10) + "T00:00:00Z") + 86400000
  return { from: sql(from), to: sql(to), fromSeconds: from / 1000, toSeconds: to / 1000, hourly: clampDays(String(days)) === 1, step: stepHours(days, filters) }
}

// filters -> SQL conditions over `col`, with `lit` turning a validated value into SQL (a quoted
// literal for AE, a ? placeholder for SQLite)
export function filterSql(filters, col, lit) {
  const parts = []
  for (const k of ["country", "city", "asn", "path", "ip"]) if (filters[k]) parts.push(`${col[k]} = ${lit(filters[k])}`)
  if (filters.class) parts.push(classSql(filters.class, col))
  if (filters.view === "sink") parts.push(`${col.sink} != ''`)
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
  const base = `FROM ${config.dataset} WHERE timestamp >= toDateTime('${w.from}') AND timestamp < toDateTime('${w.to}')` + hostSql(h, config, "index1", (v) => `'${v}'`)
  const from = base + filterSql(f, c, (v) => `'${v}'`)
  // the map shows every place, the selected country or city highlighted: its own filters skip those
  const { country, city, ...rest } = f
  const fromPlaces = base + filterSql(rest, c, (v) => `'${v}'`)
  const n = "SUM(_sample_interval) AS n"
  const ok = "blob5 >= '200' AND blob5 < '300'"
  // tables of people (cities, visitors) follow a class filter when there is one, and show everyone
  // in the sinkhole view, which is mostly bots
  const people = f.class || f.view === "sink" ? "" : ` AND ${classSql("human", c)}`
  const human = classSql("human", c)
  return {
    totals: `SELECT index1 AS host, blob5 AS status, ${n} ${from} GROUP BY host, status FORMAT JSON`,
    // requests per hour, or per 6 hours beyond a week (aligned to 00, 06, 12 and 18 UTC)
    daily: `SELECT toStartOfInterval(timestamp, INTERVAL '${w.step}' HOUR) AS day, index1 AS host, ${n} ${from} GROUP BY day, host ORDER BY day FORMAT JSON`,
    ok: `SELECT index1 AS host, blob1 AS path, blob2 AS referer, blob3 AS ua, blob4 AS country, blob6 AS bot, blob8 AS method, blob12 AS asorg, ${n} ${from} AND ${ok} AND blob3 != '' GROUP BY host, path, referer, ua, country, bot, method, asorg ORDER BY n DESC, host, path, referer, ua, country, bot, method, asorg LIMIT ${OK_LIMIT} FORMAT JSON`,
    paths: `SELECT index1 AS host, blob1 AS path, blob5 AS status, ${n} ${from} GROUP BY host, path, status ORDER BY n DESC, host, path, status LIMIT 500 FORMAT JSON`,
    origins: `SELECT index1 AS host, blob7 AS origin, ${n} ${from} AND blob7 != '' GROUP BY host, origin ORDER BY n DESC, host, origin LIMIT 50 FORMAT JSON`,
    geo: `SELECT index1 AS host, blob4 AS country, blob10 AS region, blob9 AS city, blob15 AS lat, blob16 AS lon, ${n} ${from} AND ${ok} AND blob9 != ''${people} GROUP BY host, country, region, city, lat, lon ORDER BY n DESC, host, country, region, city, lat, lon LIMIT ${LIMITS.geo} FORMAT JSON`,
    // the selected places sort first (sel), so the LIMIT never drops them
    places: `SELECT index1 AS host, blob4 AS country, blob10 AS region, blob9 AS city, blob15 AS lat, blob16 AS lon, ${country ? `if(blob4 = '${country}'${city ? ` AND blob9 = '${city}'` : ""}, 1, 0)` : "0"} AS sel, ${n} ${fromPlaces} AND ${ok} AND blob9 != '' AND blob15 != ''${rest.class || rest.view === "sink" ? "" : ` AND ${classSql("human", c)}`} GROUP BY host, country, region, city, lat, lon, sel ORDER BY sel DESC, n DESC, host, country, region, city, lat, lon LIMIT ${LIMITS.geo} FORMAT JSON`,
    networks: `SELECT index1 AS host, blob11 AS asn, blob12 AS asorg, ${n} ${from} AND blob11 != '' GROUP BY host, asn, asorg ORDER BY n DESC, host, asn, asorg LIMIT ${LIMITS.networks} FORMAT JSON`,
    agents: `SELECT index1 AS host, blob3 AS ua, blob6 AS bot, blob12 AS asorg, ${n} ${from} AND NOT ${human} GROUP BY host, ua, bot, asorg ORDER BY n DESC, host, ua, bot, asorg LIMIT ${LIMITS.agents} FORMAT JSON`,
    visitors: `SELECT index1 AS host, toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day, count(DISTINCT blob13) AS v ${from} AND blob13 != ''${people} GROUP BY host, day FORMAT JSON`,
    // the chart's: distinct visitors per hour (or 6-hour) bucket; the per-day counts stay the total
    visitorsHours: `SELECT index1 AS host, toStartOfInterval(timestamp, INTERVAL '${w.step}' HOUR) AS day, count(DISTINCT blob13) AS v ${from} AND blob13 != ''${people} GROUP BY host, day FORMAT JSON`,
    ips: `SELECT index1 AS host, blob14 AS ip, blob12 AS asorg, blob4 AS country, ${n} ${from} AND blob14 != '' GROUP BY host, ip, asorg, country ORDER BY n DESC, host, ip, asorg, country LIMIT ${LIMITS.ips} FORMAT JSON`,
    // the sinkhole view: bait served by kind, and every canary use with the probe it came from
    ...(f.view === "sink"
      ? {
        sinkkinds: `SELECT blob17 AS kind, index1 AS host, ${n} ${from} GROUP BY kind, host ORDER BY n DESC, kind, host LIMIT 200 FORMAT JSON`,
        sinkuse: `SELECT toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS at, index1 AS host, blob1 AS path, blob17 AS kind, blob18 AS ctx, blob14 AS ip, blob12 AS asorg, blob4 AS country, blob3 AS ua, blob8 AS method, ${n} ${from} AND blob17 LIKE 'use:%' GROUP BY at, host, path, kind, ctx, ip, asorg, country, ua, method ORDER BY at DESC, host, path, kind, ctx, ip, asorg, country, ua, method LIMIT ${LIMITS.canaries} FORMAT JSON`
      }
      : {}),
    // every host in the window, whatever the selection and filters: the service chips
    hosts: `SELECT index1 AS host, ${n} FROM ${config.dataset} WHERE timestamp >= toDateTime('${w.from}') AND timestamp < toDateTime('${w.to}') GROUP BY host ORDER BY n DESC, host LIMIT 200 FORMAT JSON`,
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

// a referer from the same host, or another name of the same service, is not a referral
function externalReferer(row, config) {
  if (!row.referer) return ""
  const host = normalizeHost(row.referer.replace(/^https?:\/\//, "").split("/")[0].split(":")[0])
  return host === normalizeHost(row.host) || serviceOf(host, config) === serviceOf(row.host, config) ? "" : row.referer
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
export function build({ totals = [], daily = [], ok = [], paths = [], origins = [], geo = [], places = null, networks = [], agents = [], visitors = [], visitorsHours = [], ips = [], heat = [], hosts: seen = [], sinkkinds = [], sinkuse = [] }, config, { hourly = false, filtered = false } = {}) {
  const classify = classifier()
  const hosts = new Map()
  const get = (raw) => {
    const name = normalizeHost(raw)
    if (!hosts.has(name)) {
      hosts.set(name, {
        host: name, requests: 0, ok2xx: 0, humans2xx: 0, pageviews: 0, bots: 0, visitors: 0, status: new Map(), daily: new Map(), pages: new Map(),
        referers: new Map(), countries: new Map(), browsers: new Map(), probes: new Map(), targets: new Map(), origins: new Map(),
        cities: new Map(), networks: new Map(), classes: new Map(), agents: new Map(), ips: new Map(), names: new Map(),
        // unique visitors per day: "YYYY-MM-DD" -> visitors
        visitorsDaily: new Map(),
        // unique visitors per hour bucket: "YYYY-MM-DD HH" -> visitors, for the chart
        visitorsHourly: new Map(),
        // map points: "lat,lon|country|city" -> { lat, lon, n, label, country }
        places: new Map()
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
  // requests by "YYYY-MM-DD HH": the start of each hour (or 6-hour) bucket
  for (const r of daily) add(get(r.host).daily, String(r.day).slice(0, 13), num(r.n))
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
    const ref = externalReferer(r, config)
    if (ref) add(h.referers, ref, n)
  }
  for (const r of paths) {
    const h = get(r.host)
    const n = num(r.n)
    if (r.status === "404" || PROBE.test(r.path)) add(h.probes, r.path, n)
    // a proxy's aliases and dotted names are the proxy too
    const proxy = config.proxyHosts.has(normalizeHost(r.host)) || config.proxyHosts.has(serviceOf(r.host, config))
    if (proxy && TARGET.test(r.path) && !PROBE.test(r.path) && !isAsset(r.path)) add(h.targets, r.path, n)
  }
  for (const r of origins) add(get(r.host).origins, r.origin, num(r.n))
  for (const r of geo) add(get(r.host).cities, [r.city, r.region, r.country].filter(Boolean).join(", "), num(r.n))
  // the map: every place in view (the places query skips the country and city filters, so the
  // selection is highlighted, not alone); a result set without it falls back to the cities rows.
  // Kept apart from the hosts: a place outside the filters must not add a host to the report.
  const mapPlaces = new Map()
  for (const r of places || geo) {
    const lat = Number(r.lat)
    const lon = Number(r.lon)
    // rows from before coordinates have none ("" reads as 0, so both must be set)
    if (r.lat === "" || r.lon === "" || r.lat === undefined || !Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) continue
    // the place, not just the point: two cities can round to the same coordinates
    const key = `${lat.toFixed(2)},${lon.toFixed(2)}|${r.country || ""}|${r.city || ""}`
    const p = mapPlaces.get(key) || { lat, lon, n: 0, label: [r.city, r.region, r.country].filter(Boolean).join(", "), country: r.country || "", city: r.city || "" }
    p.n += num(r.n)
    mapPlaces.set(key, p)
    // per host too, for the API, only for hosts the filtered report has
    const h = hosts.get(normalizeHost(r.host))
    if (h) {
      const q = h.places.get(key) || { lat, lon, n: 0, label: [r.city, r.region, r.country].filter(Boolean).join(", "), country: r.country || "", city: r.city || "" }
      q.n += num(r.n)
      h.places.set(key, q)
    }
  }
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
  for (const r of visitors) {
    const h = get(r.host)
    h.visitors += num(r.v)
    add(h.visitorsDaily, String(r.day).slice(0, 10), num(r.v))
  }
  for (const r of visitorsHours) add(get(r.host).visitorsHourly, String(r.day).slice(0, 13), num(r.v))
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
  model.places = mapPlaces
  model.hourly = hourly
  // the sinkhole view: bait by kind ("bait:env" -> n) and canary uses, newest first
  model.sinkkinds = new Map()
  for (const r of sinkkinds) model.sinkkinds.set(String(r.kind), (model.sinkkinds.get(String(r.kind)) || 0) + num(r.n))
  model.canaries = sinkuse.map((r) => {
    // the probe the key came from: "<host>|<ip>|<when>|<kind>", or empty when it couldn't be read
    const parts = String(r.ctx || "").split("|")
    const [host, ip, at, kind] = parts
    const from = parts.length === 4 && HOSTNAME.test(normalizeHost(host)) && BAIT_KINDS.includes(kind) ? { host: normalizeHost(host), ip, at, kind } : null
    return { at: String(r.at).slice(0, 16), host: normalizeHost(r.host), path: r.path, kind: String(r.kind).replace(/^use:/, ""), ip: r.ip || "", asorg: r.asorg || "", country: r.country || "", ua: r.ua || "", method: r.method || "", n: num(r.n), from }
  })
  // every host in the window, for the service chips (a Map: normalized host -> requests)
  model.hosts = new Map()
  for (const r of seen) model.hosts.set(normalizeHost(r.host), (model.hosts.get(normalizeHost(r.host)) || 0) + num(r.n))
  // requests by weekday (1 = Monday) and UTC hour, all hosts in the filter
  model.heat = Array.from({ length: 7 }, () => new Array(24).fill(0))
  for (const r of heat) {
    const d = num(r.dow)
    const hr = num(r.hr)
    if (d >= 1 && d <= 7 && hr >= 0 && hr < 24) model.heat[d - 1][hr] += num(r.n)
  }
  return model
}

// "YYYY-MM-DD HH" -> n summed into "YYYY-MM-DD" -> n, sorted
const perDay = (series) => {
  const days = new Map()
  for (const [k, n] of series) days.set(k.slice(0, 10), (days.get(k.slice(0, 10)) || 0) + n)
  return [...days.entries()].sort()
}

// The model as plain JSON (Maps become [key, count] lists, top first), for /api/report and the CLI
export function toJSON(model, config, { days, host, filters = {} } = {}) {
  const top = (map) => [...map.entries()].sort((a, b) => b[1] - a[1])
  return {
    days, host: host || null, filters, partial: Boolean(model.partial), heat: model.heat,
    ...(filters.view === "sink" ? { sink: { bait: [...(model.sinkkinds || [])].sort((a, b) => b[1] - a[1]), canaries: model.canaries || [] } } : {}),
    hosts: model.map((h) => ({
      host: h.host, service: serviceOf(h.host, config), description: config.services[h.host] || config.services[serviceOf(h.host, config)] || null,
      requests: h.requests, ok2xx: h.ok2xx, pageviews: h.pageviews, bots: h.bots, visitors: h.visitors, visitorsDaily: [...h.visitorsDaily.entries()].sort(), visitorsHourly: [...h.visitorsHourly.entries()].sort(),
      status: top(h.status), daily: perDay(h.daily), hours: [...h.daily.entries()].sort(), pages: top(h.pages), referers: top(h.referers),
      countries: top(h.countries), browsers: top(h.browsers), probes: top(h.probes), targets: top(h.targets), origins: top(h.origins),
      cities: top(h.cities), networks: top(h.networks).map(([asn, n]) => [asn, h.names.get(`as:${asn}`) || "", n]),
      classes: top(h.classes), agents: top(h.agents).map(([k, n]) => [k.slice(0, k.indexOf("\t")), k.slice(k.indexOf("\t") + 1), n]),
      ips: top(h.ips).map(([ip, n]) => [ip, h.names.get(`ip:${ip}`) || "", n]),
      places: [...h.places.values()].sort((a, b) => b.n - a.n).map((p) => [p.label, p.lat, p.lon, p.n])
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

// ---- charts --------------------------------------------------------------------------------
// Inline SVG and CSS only (the page runs no script). Hovering a point, cell, slice or place shows
// its label at once (a hidden group that CSS :hover reveals); a <title> carries the same text for
// screen readers and touch.

// A hover label at (x, y), kept inside the chart's box (ox, oy, w, h); size is the font size in
// chart units
function tipBox(x, y, text, w, h, size = 11, ox = 0, oy = 0) {
  const r = (v) => +v.toFixed(2)
  const tw = text.length * size * 0.58 + size
  const th = size * 1.8
  const bx = Math.min(Math.max(ox + size * 0.1, x + size * 0.8), ox + w - tw - size * 0.1)
  const by = Math.min(Math.max(oy + size * 0.1, y - th - size * 0.6), oy + h - th - size * 0.1)
  return `<g class="tip"><rect x="${r(bx)}" y="${r(by)}" width="${r(tw)}" height="${r(th)}" rx="${r(size * 0.4)}"/><text x="${r(bx + size * 0.5)}" y="${r(by + size * 1.25)}" font-size="${r(size)}">${escapeHtml(text)}</text></g>`
}

// 1, 2, 2.5 or 5 times a power of ten, at least v: the top of a chart's scale
function niceMax(v) {
  if (v <= 0) return 1
  const p = 10 ** Math.floor(Math.log10(v))
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v)
}
const short = (n) => (n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${+(n / 1e3).toFixed(1)}k` : String(+n.toFixed(1)))
const DOW = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
// "2026-10-06" -> "Tue 10-06", "2026-10-06 14" -> "10-06 14:00"
const weekday = (day) => DOW[(new Date(`${day.slice(0, 10)}T00:00:00Z`).getUTCDay() + 6) % 7]
// "2026-10-06" -> "Tue 10-06", "2026-10-06 14" -> "Tue 10-06 14:00 UTC"
const keyLabel = (k) => (k.length > 10 ? `${weekday(k)} ${k.slice(5, 10)} ${k.slice(11)}:00 UTC` : `${weekday(k)} ${k.slice(5)}`)

// A line chart over the window's keys (days, or a day's hours), zero-filled, like Cloudflare's:
// gridlines with values, a few x labels, a filled line, and per point a hover column with a guide,
// a dot and its label. dayLink(key), when given, makes a day's column a link into that day.
const CW = 720
const CH = 170
function lineChart(series, window, noun, dayLink = null) {
  const vals = window.map((k) => series.get(k) || 0)
  if (!vals.some(Boolean)) return ""
  const max = niceMax(Math.max(...vals))
  const L = 40
  const R = 10
  const T = 10
  const B = 24
  const span = CW - L - R
  const x = (i) => L + (window.length === 1 ? span / 2 : (i * span) / (window.length - 1))
  const y = (v) => T + (CH - T - B) * (1 - v / max)
  const fx = (n) => n.toFixed(1)
  const grid = [0, 1, 2, 3, 4].map((t) => {
    const v = (max * t) / 4
    return `<line class="g" x1="${L}" x2="${CW - R}" y1="${fx(y(v))}" y2="${fx(y(v))}"/><text class="ax" x="${L - 6}" y="${fx(y(v) + 4)}" text-anchor="end">${short(v)}</text>`
  }).join("")
  // x labels: dates at midnight when the keys span several days, else every few hours or days
  const days = new Set(window.map((k) => k.slice(0, 10))).size
  const marks = window.length > 1 && window[0].length > 10 && days > 1
    ? window.map((k, i) => [k, i]).filter(([k]) => k.endsWith(" 00")).filter((_, j, a) => j % Math.ceil(a.length / 7) === 0)
    : window.map((k, i) => [k, i]).filter(([, i]) => i % Math.max(1, Math.ceil(window.length / 7)) === 0)
  const xlabels = marks.map(([k, i]) => `<text class="ax" x="${fx(x(i))}" y="${CH - 6}" text-anchor="middle">${escapeHtml(k.length > 10 && days === 1 ? `${k.slice(11)}:00` : k.slice(5, 10))}</text>`).join("")
  const pts = vals.map((v, i) => `${fx(x(i))},${fx(y(v))}`)
  const line = `M${pts.join("L")}`
  const area = `${line}L${fx(x(vals.length - 1))},${fx(y(0))}L${fx(x(0))},${fx(y(0))}Z`
  // a point's hit area runs from the midpoint with its left neighbour to the one with its right, the
  // first and last stopping at the plot's edges
  const left = (i) => (i === 0 ? L : (x(i - 1) + x(i)) / 2)
  const right = (i) => (i === window.length - 1 ? CW - R : (x(i) + x(i + 1)) / 2)
  const hover = window.map((k, i) => {
    const text = `${keyLabel(k)}: ${fmt(vals[i])} ${noun}`
    // the hover label is the text; aria-label says it to a screen reader (a <title> would also pop
    // up the browser's own tooltip)
    const g = `<g class="pt" aria-label="${escapeHtml(text)}"><rect class="hit" x="${fx(left(i))}" y="${T}" width="${fx(right(i) - left(i))}" height="${CH - T - B}"/><line class="guide" x1="${fx(x(i))}" x2="${fx(x(i))}" y1="${T}" y2="${CH - B}"/><circle cx="${fx(x(i))}" cy="${fx(y(vals[i]))}" r="${window.length > 60 ? 2.5 : 3.5}"/>${tipBox(x(i), y(vals[i]), text, CW, CH)}</g>`
    return dayLink && vals[i] ? `<a href="${dayLink(k.slice(0, 10))}">${g}</a>` : g
  }).join("")
  return `<svg class="line" viewBox="0 0 ${CW} ${CH}" role="img" aria-label="${escapeHtml(noun)}, ${escapeHtml(window[0])} to ${escapeHtml(window[window.length - 1])}, peak ${fmt(Math.max(...vals))}">${grid}${xlabels}<path class="area" d="${area}"/><path class="stroke" d="${line}"/>${hover}</svg>`
}

// A labelled chart row: the name and total on the left, the chart on the right
const chartRow = (name, total, svg, unit = "") => (svg ? `<div class="chart"><div><p class="cap">${escapeHtml(name)}</p><p class="big">${fmt(total)}</p>${unit ? `<p class="muted unit">${escapeHtml(unit)}</p>` : ""}</div>${svg}</div>` : "")

// The one script the page runs: wheel (and trackpad pinch) zooms the map around the cursor, a drag
// pans it, circles and labels keep their size on screen, and a drag never counts as a click. It
// only changes the map's viewBox, circle radii and label transforms, and reads nothing written by
// a client. The CSP allows exactly this text by its hash (MAP_SCRIPT_HASH, checked by a test), so
// change both together. Without it the map still works: clicks are links, zoom is the selection's.
export const MAP_SCRIPT = `(function () {
  var W = 720, H = 288, MIN = 24
  function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }
  document.querySelectorAll("svg.map").forEach(function (svg) {
    var vb = svg.getAttribute("viewBox").split(" ").map(Number)
    var x = vb[0], y = vb[1], w = vb[2], h = vb[3], w0 = w
    var circles = Array.prototype.map.call(svg.querySelectorAll("circle"), function (c) { return [c, Number(c.getAttribute("r"))] })
    var tips = Array.prototype.map.call(svg.querySelectorAll(".pt"), function (g) {
      var c = g.querySelector("circle")
      return [g.querySelector(".tip"), c.getAttribute("cx"), c.getAttribute("cy")]
    })
    function draw() {
      var s = w / w0
      svg.setAttribute("viewBox", [x, y, w, h].join(" "))
      circles.forEach(function (c) { c[0].setAttribute("r", c[1] * s) })
      tips.forEach(function (t) {
        if (t[0]) t[0].setAttribute("transform", "translate(" + t[1] + " " + t[2] + ") scale(" + s + ") translate(" + -t[1] + " " + -t[2] + ")")
      })
    }
    svg.addEventListener("wheel", function (e) {
      e.preventDefault()
      var box = svg.getBoundingClientRect()
      var px = x + (e.clientX - box.left) / box.width * w, py = y + (e.clientY - box.top) / box.height * h
      var dy = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? box.height : 1)
      var nw = clamp(w * Math.exp(clamp(dy, -100, 100) * 0.004), MIN, W)
      var nh = nw * H / W
      x = clamp(px - (px - x) * nw / w, 0, W - nw)
      y = clamp(py - (py - y) * nh / h, 0, H - nh)
      w = nw
      h = nh
      draw()
    }, { passive: false })
    // one primary, left-button pointer drags, followed on the whole window; the click that ends a
    // drag is swallowed, nothing else (a keyboard click has detail 0 and is never touched)
    var drag = null, swallow = false
    function stop() { drag = null }
    svg.addEventListener("pointerdown", function (e) {
      if (!e.isPrimary || e.button !== 0) return
      drag = { id: e.pointerId, cx: e.clientX, cy: e.clientY, x: x, y: y, moved: false }
    })
    window.addEventListener("pointermove", function (e) {
      if (!drag || e.pointerId !== drag.id) return
      if (!(e.buttons & 1)) return stop()
      if (!drag.moved && Math.abs(e.clientX - drag.cx) + Math.abs(e.clientY - drag.cy) < 5) return
      drag.moved = true
      var box = svg.getBoundingClientRect()
      x = clamp(drag.x - (e.clientX - drag.cx) / box.width * w, 0, W - w)
      y = clamp(drag.y - (e.clientY - drag.cy) / box.height * h, 0, H - h)
      draw()
    })
    window.addEventListener("pointerup", function (e) {
      if (!drag || e.pointerId !== drag.id) return
      if (drag.moved) {
        swallow = true
        setTimeout(function () { swallow = false }, 0)
      }
      stop()
    })
    // only the dragging pointer's own cancel or capture loss ends it (a second finger lifting
    // releases its own capture); a blur ends any drag
    function stopFor(e) { if (drag && e.pointerId === drag.id) stop() }
    window.addEventListener("pointercancel", stopFor)
    window.addEventListener("blur", stop)
    svg.addEventListener("lostpointercapture", stopFor)
    svg.addEventListener("click", function (e) {
      if (swallow && e.detail > 0) { e.preventDefault(); e.stopPropagation() }
      swallow = false
    }, true)
  })
})()`
export const MAP_SCRIPT_HASH = "sha256-W37V0N2mdG27dJBKZCQ845OBY28vbmnKPSsfnWpaagM="

// Visitors by city on a world map: land is the outline from src/world.js (passed in, so this file
// stays import-free), one circle per place, its area proportional to its count. Same projection as
// the outline: x = (lon + 180) * 2, y = (84 - lat) * 2. A circle selects its city (state.country
// and state.city), and the selection turns orange, is drawn on top, and the map zooms to it; with
// a selection, a click anywhere else on the map drops it. No script: every click is a link.
const MAP_PLACES = 300
const mapX = (p) => (p.lon + 180) * 2
const mapY = (p) => (84 - Math.max(-60, Math.min(84, p.lat))) * 2
function worldMap(places, land, state) {
  if (!land || !places.size) return ""
  const picked = (p) => Boolean(state.country) && p.country === state.country && (!state.city || p.city === state.city)
  // the selection always makes the map, then the busiest of the rest up to the cap
  const all = [...places.values()].sort((a, b) => b.n - a.n)
  const selectedAll = all.filter(picked)
  const chosen = selectedAll.slice(0, MAP_PLACES)
  const list = [...chosen, ...all.filter((p) => !picked(p)).slice(0, MAP_PLACES - chosen.length)].sort((a, b) => b.n - a.n)
  const max = list[0].n
  const sel = list.filter(picked)
  // the view: the selection's bounds, padded, at least 18 degrees wide, at the map's 2.5:1
  let vb = [0, 0, 720, 288]
  // the frame covers every selected place, drawn or not
  if (selectedAll.length) {
    const xs = selectedAll.map(mapX)
    const ys = selectedAll.map(mapY)
    let w = Math.max(Math.max(...xs) - Math.min(...xs) + 24, 36)
    let h = Math.max(Math.max(...ys) - Math.min(...ys) + 24, 14.4)
    if (w / h > 2.5) h = w / 2.5
    else w = h * 2.5
    w = Math.min(w, 720)
    h = Math.min(h, 288)
    const cx = (Math.max(...xs) + Math.min(...xs)) / 2
    const cy = (Math.max(...ys) + Math.min(...ys)) / 2
    vb = [Math.min(Math.max(0, cx - w / 2), 720 - w), Math.min(Math.max(0, cy - h / 2), 288 - h), w, h]
  }
  // circles and labels keep their size on screen at any zoom
  const k = vb[2] / 720
  const r = (p) => (1.6 + 7 * Math.sqrt(p.n / max)) * k
  const f = (v) => +v.toFixed(2)
  // biggest first so small circles stay on top, and the selection over everything
  const order = [...list.filter((p) => !picked(p)), ...sel]
  const dots = order.map((p) => `<circle cx="${f(mapX(p))}" cy="${f(mapY(p))}" r="${f(r(p))}"${picked(p) ? ` class="sel"` : ""}/>`).join("")
  const hits = order.map((p) => {
    const text = `${p.label}: ${fmt(p.n)}`
    // a click selects the city; on the selected city it drops the selection
    const valid = parseFilters(new URLSearchParams({ country: p.country, city: p.city }))
    const next = picked(p) && state.city ? { country: null, city: null } : { country: valid.country || null, city: valid.country ? valid.city || null : null }
    const g = `<g class="pt" aria-label="${escapeHtml(text)}"><circle class="hit" cx="${f(mapX(p))}" cy="${f(mapY(p))}" r="${f(Math.max(r(p), 3 * k))}"/>${tipBox(mapX(p), mapY(p), text, vb[2], vb[3], 9 * k, vb[0], vb[1])}</g>`
    return next.country || picked(p) ? `<a href="${hrefFor(state, next)}">${g}</a>` : g
  }).join("")
  // the whole world, so a click off the circles deselects wherever the script zooms or pans to
  const sea = sel.length ? `<a href="${hrefFor(state, { country: null, city: null })}" aria-label="show the whole world"><rect class="sea" x="0" y="0" width="720" height="288"/></a>` : ""
  return `<svg class="map" viewBox="${vb.map(f).join(" ")}" role="img" aria-label="visitors by city, ${list.length} places${sel.length ? `, ${sel.length} selected` : ""}">${sea}<path class="land" d="${land}"/>${dots}${hits}</svg>`
}

// Requests by weekday and UTC hour: one cell per hour, its opacity proportional to the busiest.
// The colored cells come first; on top, a transparent hit area per cell holds its hover label, so a
// label is never covered by a later cell (SVG paints in order and has no z-index).
function heatmap(heat) {
  const max = Math.max(0, ...heat.flat())
  if (!max) return ""
  const cells = heat.map((row, d) => row.map((v, h) => `<rect x="${24 + h * 10}" y="${d * 10}" width="9" height="9" style="opacity:${v ? (0.15 + 0.85 * v / max).toFixed(2) : 0.06}"/>`).join("")).join("")
  const hits = heat.map((row, d) => row.map((v, h) => {
    const text = `${DOW[d]} ${String(h).padStart(2, "0")}:00 UTC: ${fmt(v)} requests`
    return `<g class="pt" aria-label="${escapeHtml(text)}"><rect class="hit" x="${24 + h * 10}" y="${d * 10}" width="10" height="10"/><rect class="ring" x="${24 + h * 10}" y="${d * 10}" width="9" height="9"/>${tipBox(24 + h * 10 + 4, d * 10, text, 264, 82, 6)}</g>`
  }).join("")).join("")
  const labels = DOW.map((d, i) => `<text x="0" y="${i * 10 + 8}">${d}</text>`).join("")
  const hours = [0, 6, 12, 18, 23].map((h) => `<text x="${24 + h * 10}" y="80">${String(h).padStart(2, "0")}</text>`).join("")
  return `<svg class="heat" viewBox="0 0 264 82" role="img" aria-label="requests by weekday and hour, UTC, busiest ${max}">${labels}${cells}${hours}${hits}</svg>`
}

// eight distinct colors per class, as many as the donut shows slices: a code never shares one
const STATUS_COLORS = {
  c2: ["#2e9e63", "#8fd19e", "#1f6b45", "#5bbf8a", "#b8e3c4", "#3f8f6f", "#72a85a", "#0f4f33"],
  c3: ["#3b6fe0", "#9a6be0", "#4fb3e8", "#7f8fd8", "#2a4fa8", "#c3a6f0", "#1f8ab8", "#5a3fa8"],
  c4: ["#e0821a", "#f2c230", "#b7462a", "#f3a08e", "#8c5a2b", "#d6a26b", "#e85d1f", "#f6e08a"],
  c5: ["#d23b3b", "#e5579e", "#8f1d2c", "#f08a8a", "#b02d6e", "#ff5c5c", "#6b1220", "#f2a7c8"],
  co: ["#8a919d", "#b9bec8", "#5f6670", "#a4abb6", "#757c87", "#cdd1d8", "#4a5059", "#969ea9"]
}
// "other" (the codes past the eighth) has its own warm gray, in no class's list
const OTHER_COLOR = "#a8977c"
// Status codes as a donut: a slice per code (the top 8, the rest as "other"), colored by class
// (2xx green, 3xx blue, 4xx orange, 5xx red), lighter for the less common codes of a class. The
// center shows the total, or the hovered slice's code, count and share; a legend lists them all.
function statusPie(status) {
  const total = [...status.values()].reduce((s, v) => s + v, 0)
  if (!total) return ""
  const sorted = [...status].sort((a, b) => b[1] - a[1])
  const slices = sorted.slice(0, 8)
  const rest = sorted.slice(8).reduce((t, [, v]) => t + v, 0)
  if (rest) slices.push(["other", rest])
  const cls = (k) => (/^[2-5]\d\d$/.test(k) ? `c${k[0]}` : "co")
  // each code its own color, distinct within its class: the class's hue first, then clearly
  // different ones (4xx: orange, yellow, rust, salmon, brown), readable on light and dark
  const seen = new Map()
  const color = (k) => {
    if (k === "other") return OTHER_COLOR
    const list = STATUS_COLORS[cls(k)]
    const n = seen.get(cls(k)) || 0
    seen.set(cls(k), n + 1)
    return list[n % list.length]
  }
  const C = 70
  const RO = 62
  const RI = 38
  const pt = (r, a) => `${(C + r * Math.sin(a)).toFixed(2)},${(C - r * Math.cos(a)).toFixed(2)}`
  let a0 = 0
  const pct = (v) => (v / total < 0.001 ? "<0.1%" : `${((v / total) * 100).toFixed(v / total < 0.1 ? 1 : 0)}%`)
  const parts = slices.map(([k, v]) => {
    const a1 = a0 + (v / total) * 2 * Math.PI
    // a whole circle can't be one arc: two halves
    const d = v === total
      ? `M${pt(RO, 0)}A${RO},${RO} 0 1 1 ${pt(RO, Math.PI)}A${RO},${RO} 0 1 1 ${pt(RO, 0)}M${pt(RI, 0)}A${RI},${RI} 0 1 0 ${pt(RI, Math.PI)}A${RI},${RI} 0 1 0 ${pt(RI, 0)}Z`
      : `M${pt(RO, a0)}A${RO},${RO} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${pt(RO, a1)}L${pt(RI, a1)}A${RI},${RI} 0 ${a1 - a0 > Math.PI ? 1 : 0} 0 ${pt(RI, a0)}Z`
    a0 = a1
    const text = `${k}: ${fmt(v)} (${pct(v)})`
    const fill = color(k)
    return { k, v, fill, svg: `<g class="pt" aria-label="${escapeHtml(text)}"><path d="${d}" fill-rule="evenodd" style="fill:${fill}"/><text class="ctr" x="${C}" y="${C - 2}" text-anchor="middle">${escapeHtml(k)}</text><text class="ctr sub" x="${C}" y="${C + 14}" text-anchor="middle">${fmt(v)} · ${pct(v)}</text></g>` }
  })
  const legend = parts.map(({ k, v, fill }) => `<li><i style="background:${fill}"></i><b>${escapeHtml(k)}</b> ${fmt(v)} <span class="muted">${pct(v)}</span></li>`).join("")
  return `<div class="statusbox"><svg class="pie" viewBox="0 0 140 140" role="img" aria-label="status codes: ${escapeHtml(parts.map(({ k, v }) => `${k} ${pct(v)}`).join(", "))}"><text class="total" x="${C}" y="${C - 2}" text-anchor="middle">${short(total)}</text><text class="total sub" x="${C}" y="${C + 14}" text-anchor="middle">requests</text>${parts.map((p) => p.svg).join("")}</svg><ul class="pielegend">${legend}</ul></div>`
}

// one formatter for every number on the page: toLocaleString builds one per call
const NUMBER = new Intl.NumberFormat("en-US")
const fmt = (n) => NUMBER.format(n)

// when the detail query is capped, humans are a lower bound, so bots (2xx - humans) are an upper bound
const shareText = (share, capped) => (capped ? `≤${share}%` : `${share}%`)

// Hosts folded into services (aliases and trailing dots count as their service), every breakdown
// summed across them. With more than one service in view, page and probe rows carry their service.
// A row's unit is the selected item that covers its host (so narrowing keeps "name!" and alias
// selections as they are), or with nothing selected its service.
function combine(model, config, host = null) {
  const add = (map, k, n) => map.set(k, (map.get(k) || 0) + n)
  const merge = (to, from, key = (k) => k) => { for (const [k, n] of from) add(to, key(k), n) }
  // host -> its unit, worked out once per host: the first selected item covering it, else its service
  // a domain selection still breaks down by service: only names and services are units
  const items = (host ? host.split(",") : []).filter((item) => !item.startsWith("*.")).map((item) => [item, new Set(coveredHosts(item, config))])
  const units = new Map()
  const unitOf = (h) => {
    if (!units.has(h)) units.set(h, items.find(([, covered]) => covered.has(h))?.[0] || serviceOf(h, config))
    return units.get(h)
  }
  const services = new Map()
  for (const h of model) {
    const name = unitOf(h.host)
    const s = services.get(name) || { service: name, requests: 0, pageviews: 0, visitors: 0, ok2xx: 0, bots: 0, hosts: new Map() }
    for (const k of ["requests", "pageviews", "visitors", "ok2xx", "bots"]) s[k] += h[k]
    add(s.hosts, h.host, h.requests)
    services.set(name, s)
  }
  const multi = services.size > 1
  const c = { services, multi, names: new Map(), hostnames: new Map(), places: model.places || new Map() }
  for (const k of ["requests", "pageviews", "visitors", "ok2xx", "bots"]) c[k] = model.reduce((t, h) => t + h[k], 0)
  for (const k of ["status", "daily", "visitorsDaily", "visitorsHourly", "referers", "countries", "cities", "browsers", "networks", "classes", "agents", "ips", "origins", "pages", "probes", "targets"]) c[k] = new Map()
  for (const h of model) {
    const svc = unitOf(h.host)
    // a page or probe key is "<unit>\t<path>" when several units are in view
    const scoped = (p) => (multi ? `${svc}\t${p}` : p)
    for (const k of ["status", "daily", "visitorsDaily", "visitorsHourly", "referers", "countries", "cities", "browsers", "networks", "classes", "agents", "ips", "origins", "targets"]) merge(c[k], h[k])
    merge(c.pages, h.pages, scoped)
    merge(c.probes, h.probes, scoped)
    for (const [k, v] of h.names) c.names.set(k, v)
    add(c.hostnames, h.host, h.requests)
  }
  return c
}

// One card for everything in view: the selected services, or all of them
function combinedSection(c, window, dayWindow, config, capped, state) {
  const share = c.ok2xx ? Math.round((c.bots / c.ok2xx) * 100) : 0
  const by = (key) => ({ link: (k) => filterLink(state, key, k) })
  const tab = (k) => k.indexOf("\t")
  // a scoped page row: "<service><path>", linking to that service and path
  const unitLabel = (u) => (u.endsWith("!") ? `${u.slice(0, -1)} (this name only)` : u)
  const scoped = c.multi
    ? { label: (k) => `${k.slice(0, tab(k)).replace(/!$/, "")}${k.slice(tab(k) + 1)}`, link: (k) => filterLink({ ...state, host: k.slice(0, tab(k)) }, "path", k.slice(tab(k) + 1)) }
    : by("path")
  const services = new Map([...c.services].map(([name, s]) => [name, s.requests]))
  const only = c.services.size === 1 ? [...c.services.keys()][0] : null
  const desc = only ? config.services[only.replace(/!$/, "")] : ""
  const named = c.hostnames.size > c.services.size
  // a host-names row selects that name alone: "name!" when it is a service with aliases
  const exact = (h) => (Object.values(config.aliases || {}).includes(h) ? `${h}!` : h)
  return `<section class="card">
${only ? `<header><h2>${escapeHtml(unitLabel(only))}${desc ? ` <span class="desc">${escapeHtml(desc)}</span>` : ""}</h2></header>` : ""}
<p class="summary"><b>${fmt(c.requests)}</b> requests · <b>${fmt(c.pageviews)}</b> human page views${c.visitors ? ` · <b>${fmt(c.visitors)}</b> unique visitors` : ""} · ${shareText(share, capped)} of 2xx from bots${capped ? " (upper bound)" : ""}</p>
${chartRow("Requests", c.requests, lineChart(c.daily, window, "requests", state.day ? null : (day) => hrefFor(state, { day })), window.length === dayWindow.length * 24 ? "per hour" : `per ${(dayWindow.length * 24) / window.length} hours`)}
${chartRow("Unique visitors", c.visitors, lineChart(c.visitorsHourly, window, "visitors", state.day ? null : (day) => hrefFor(state, { day })), window.length === dayWindow.length * 24 ? "per hour" : `per ${(dayWindow.length * 24) / window.length} hours`)}
${statusPie(c.status)}
<div class="grid">
${c.multi ? table("services", services, { label: (k) => config.services[k] ? `${k} · ${config.services[k]}` : unitLabel(k), link: (k) => hrefFor(state, { host: k }) }) : ""}${named ? table("host names", c.hostnames, { link: (k) => hrefFor(state, { host: exact(k) }) }) : ""}${table("pages", c.pages, scoped)}${table("referers", c.referers)}${table("countries", c.countries, { link: (k) => filterLink({ ...state, city: null }, "country", k) })}${table("cities", c.cities)}${table("browsers", c.browsers)}${table("networks", c.networks, { label: (asn) => `AS${asn} ${c.names.get(`as:${asn}`) || ""}`.trim(), ...by("asn") })}${table("bots and AI", c.classes, { label: classLabel, ...by("class") })}${table("agents", c.agents, { label: (k) => k.slice(tab(k) + 1), link: (k) => filterLink(state, "class", k.slice(0, tab(k))) })}${table("IP addresses", c.ips, { label: (ip) => `${ip} ${c.names.get(`ip:${ip}`) || ""}`.trim(), ...by("ip") })}${table("404s and probes", c.probes, scoped)}${table("proxy targets", c.targets)}${table("proxy callers (Origin)", c.origins)}
</div>
</section>`
}

const CSS = `:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#14171f;--muted:#5d6572;--line:#e6e8ec;--soft:#f0f2f5;--accent:#2f62d9;--accent-soft:rgba(47,98,217,.12);--c2:#2a8f5b;--c3:#2f62d9;--c4:#c27a10;--c5:#cc3b3b;--co:#8a919d;--sel:#e8710a;--range:#34495e;--range-fg:#aeb8c4;--range-end:#e74c3c}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f14;--card:#161a22;--fg:#e9ecf2;--muted:#9aa3b2;--line:#262b36;--soft:#1d222c;--accent:#7aa2ff;--accent-soft:rgba(122,162,255,.16);--c2:#4fc08a;--c3:#7aa2ff;--c4:#e0a43c;--c5:#f0716f;--co:#8a919d;--sel:#f5a04a;--range:#34495e;--range-fg:#c8d0da;--range-end:#e74c3c}}
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
.chips b,.chips a.sel{padding:2px 10px;border-radius:999px;font-size:13px;background:var(--accent);color:var(--bg);border-color:var(--accent)}
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
.chips .dom{display:inline-flex;flex-wrap:wrap;gap:4px;align-items:center;padding:2px 4px 2px 2px;border:1px solid var(--line);border-radius:999px;background:var(--soft)}
.chips .dom>a:first-child,.chips .dom>span:first-child{font-weight:600;color:var(--fg)}
.chips span.off{padding:2px 10px;border:1px dashed var(--line);border-radius:999px;font-size:13px;color:var(--muted)}
.heat{display:block;width:100%;max-width:528px;margin-top:12px;fill:var(--accent);font-size:7px}.heat text{fill:var(--muted)}
.cell a{color:inherit}.cell a:hover{color:var(--accent)}
.spark a rect{cursor:pointer}
.foot{font-size:12px;margin-top:24px}
.cal{display:flex;flex-wrap:wrap;gap:16px 32px}.cal .mon{width:280px}.cal table{width:280px;table-layout:fixed;border-collapse:collapse}
.cal .head{display:flex;align-items:center;justify-content:space-between;font-size:15px;font-weight:500;padding:0 0 8px}
.cal .nav{display:inline-flex;width:26px;height:26px;border-radius:50%;align-items:center;justify-content:center;background:var(--line);color:var(--muted);font-size:11px}.cal a.nav:hover{text-decoration:none;color:var(--fg)}
.cal th{font-size:13px;font-weight:600;padding:4px 0;text-align:center}
.cal td{padding:0;text-align:center}.cal td a,.cal td span{display:block;line-height:36px;color:var(--fg)}
.seg b a{color:inherit}.cal td a:hover{text-decoration:none;background:var(--soft)}
.cal td.out span{color:var(--muted);opacity:.5}.cal span.nav{visibility:hidden}.cal td.off span{opacity:.35}
.cal td.in{background:var(--range)}.cal td.in a{color:var(--range-fg)}.cal td.in a:hover{background:transparent}
.cal td.end{background:var(--range-end)}.cal td.end a{color:#fff;font-weight:600}
.chart{display:grid;grid-template-columns:140px 1fr;gap:12px;align-items:center;border-top:1px solid var(--line);padding:10px 0}.chart:first-of-type{border-top:0}
.chart .big{font-size:24px;font-weight:650;margin:0;font-variant-numeric:tabular-nums}.chart .cap{margin:0}.chart .unit{margin:0;font-size:12px}
.line{display:block;width:100%;height:auto;overflow:visible}.line .g{stroke:var(--line);stroke-dasharray:3 3}.line .ax{fill:var(--muted);font-size:11px}
.line .area{fill:var(--accent-soft)}.line .stroke{fill:none;stroke:var(--accent);stroke-width:2;stroke-linejoin:round}
.pt .hit{fill:transparent}.pt .guide,.line .pt circle,.pt .ring,.tip{visibility:hidden;pointer-events:none}
.pt:hover .guide,.line .pt:hover circle,.pt:hover .ring,.pt:hover .tip{visibility:visible}
.line .guide{stroke:var(--muted);stroke-width:1}.line .pt circle{fill:var(--card);stroke:var(--accent);stroke-width:2}
.tip rect{fill:var(--card);stroke:var(--line)}.tip text{fill:var(--fg);text-decoration:none}svg a,svg a:hover{text-decoration:none}
.heat .ring{fill:none;stroke:var(--fg);stroke-width:.8}
.statusbox{display:flex;flex-wrap:wrap;align-items:center;gap:8px 24px;margin:4px 0 16px}
.pie{width:140px;height:140px;flex:none}.pie path.c2{fill:var(--c2)}.pie path.c3{fill:var(--c3)}.pie path.c4{fill:var(--c4)}.pie path.c5{fill:var(--c5)}.pie path.co{fill:var(--co)}
.pie path{stroke:var(--card);stroke-width:1.5}.pie .pt:hover path{filter:brightness(1.12)}
.pie text{fill:var(--fg);font-size:15px;font-weight:650}.pie text.sub{fill:var(--muted);font-size:10px;font-weight:400}.pie .ctr{visibility:hidden}.pie .pt:hover .ctr{visibility:visible}.pie:has(.pt:hover) .total{visibility:hidden}
.pielegend{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:2px 16px;font-size:12px;flex:1;min-width:200px}
.pielegend li{display:flex;align-items:center;gap:6px;font-variant-numeric:tabular-nums}.pielegend i{width:9px;height:9px;border-radius:2px;flex:none}
.pielegend .c2{background:var(--c2)}.pielegend .c3{background:var(--c3)}.pielegend .c4{background:var(--c4)}.pielegend .c5{background:var(--c5)}.pielegend .co{background:var(--co)}
@media (max-width:520px){.chart{grid-template-columns:1fr}}
.alerts .ua{font-size:12px}.alerts .method{font-size:11px;font-weight:600;color:var(--muted)}
.alerts{margin-bottom:16px;table-layout:auto}.alerts th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;padding:2px 8px 4px 0}.alerts td{padding:3px 8px 3px 0;vertical-align:top;overflow-wrap:anywhere}
.map{display:block;width:100%;height:auto}.map .land{fill:var(--soft);stroke:var(--line);stroke-width:.6;pointer-events:none}
.map circle{fill:var(--accent);fill-opacity:.45;stroke:var(--accent);stroke-width:1}.map circle.sel{fill:var(--sel);fill-opacity:.8;stroke:var(--sel)}
.map .land,.map circle{vector-effect:non-scaling-stroke}.map .hit{fill:transparent;stroke:none}.map .sea{fill:transparent;cursor:zoom-out}
.map .tip rect{vector-effect:non-scaling-stroke}.map{cursor:grab}.map:active{cursor:grabbing}.cap .hint{text-transform:none;letter-spacing:0}.map .pt:hover .hit{fill:var(--fg);fill-opacity:.12}
@media (max-width:520px){body{padding:16px 12px 32px}.tile .v{font-size:24px}.card{padding:12px}}`

// The sinkhole card: every canary use with the probe its key came from, and bait served by kind
function sinkSection(model, state) {
  const uses = model.canaries || []
  // an IP links to its filter (in this view: everything sinkhole from it), when it is an address
  const ipCell = (ip) => {
    const href = filterLink(state, "ip", ip)
    return href ? `<a href="${href}">${escapeHtml(ip)}</a>` : escapeHtml(ip || "?")
  }
  // each use: when, who (IP, network, country, user agent), the request (method, host, path), and
  // the probe its key came from
  const rows = uses.map((u) => `<tr><td>${escapeHtml(u.at)}</td><td>${ipCell(u.ip)} <span class="muted">${escapeHtml([u.asorg, u.country].filter(Boolean).join(" · "))}</span><br><span class="muted ua">${escapeHtml(u.ua || "no user agent")}</span></td><td><b class="method">${escapeHtml(u.method || "?")}</b> ${escapeHtml(u.host + u.path)}${u.n > 1 ? ` <span class="muted">×${u.n}</span>` : ""}</td><td>${u.from ? `${escapeHtml(u.from.kind)} bait on ${escapeHtml(u.from.host)}${u.from.ip ? `, to ${ipCell(u.from.ip)}` : ""} at ${escapeHtml(u.from.at)}` : "unknown bait"}</td></tr>`).join("")
  const kinds = new Map([...(model.sinkkinds || [])].map(([k, n]) => [k, n]))
  const label = (k) => (k.startsWith("bait:") ? `${k.slice(5)} bait served` : k.startsWith("use:") ? `${k.slice(4)} key used` : k === "challenge" ? "/_internal/ without a key" : k)
  return `<section class="card"><header><h2>Sinkhole <span class="desc">Probes for secrets get bait with canary keys; a key in use points back at the probe that took it.</span></h2></header>
${uses.length ? `<table class="alerts"><caption>canary alerts</caption><tr><th>hour (UTC)</th><th>used by</th><th>request</th><th>key from</th></tr>${rows}</table>` : `<p class="muted">No canary key has been used in this window.</p>`}
<div class="grid">${table("sinkhole events", kinds, { label })}</div>
</section>`
}

// ---- calendar ------------------------------------------------------------------------------
// The custom range picker: two months side by side, Monday first, like the heatmap. Every day is a
// link: with pick=from it starts a range (and asks for its end), with pick=to it ends it (a day
// before the start starts over). The range is dark, its ends red, other months' days grey, days
// outside AE's 92 days or after today not links. No script: the page reloads per click.
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
const addMonths = (ym, k) => {
  const [y, m] = ym.split("-").map(Number)
  return new Date(Date.UTC(y, m - 1 + k, 1)).toISOString().slice(0, 7)
}
const addDays = (day, k) => new Date(Date.parse(`${day}T00:00:00Z`) + k * 86400000).toISOString().slice(0, 10)
function calendar(state, today) {
  const oldest = addDays(today, -(RETENTION_DAYS - 1))
  const firstMonth = oldest.slice(0, 7)
  const lastLeft = addMonths(today.slice(0, 7), -1) < firstMonth ? firstMonth : addMonths(today.slice(0, 7), -1)
  // the left month: as asked, else the one before the range's end (so it shows on the right)
  let left = state.cal || addMonths((state.to || state.from || today).slice(0, 7), -1)
  if (left < firstMonth) left = firstMonth
  if (left > lastLeft) left = lastLeft
  const picking = state.pick === "to" && state.from ? "to" : "from"
  const from = state.from || ""
  const to = picking === "to" ? "" : state.to || ""
  const day = (d, month) => {
    // the other months' days fill the grid, in gray: they're picked in their own month
    if (d.slice(0, 7) !== month) return `<td class="out"><span>${Number(d.slice(8))}</span></td>`
    const cls = [d === from || d === to ? "end" : from && to && d > from && d < to ? "in" : ""].filter(Boolean)
    const ok = d >= oldest && d <= today
    if (!ok) cls.push("off")
    const next = picking === "to" && d >= from ? { from, to: d, pick: null, cal: null, day: null } : { from: d, to: null, pick: "to", cal: left, day: null }
    const n = Number(d.slice(8))
    return `<td${cls.length ? ` class="${cls.join(" ")}"` : ""}>${ok ? `<a href="${hrefFor(state, next)}">${n}</a>` : `<span>${n}</span>`}</td>`
  }
  const month = (ym, prev, next) => {
    const first = `${ym}-01`
    const start = addDays(first, -((new Date(`${first}T00:00:00Z`).getUTCDay() + 6) % 7))
    const weeks = Array.from({ length: 6 }, (_, w) => `<tr>${Array.from({ length: 7 }, (_, i) => day(addDays(start, w * 7 + i), ym)).join("")}</tr>`).join("")
    const nav = (dir, ok, target) => (ok ? `<a class="nav" href="${hrefFor(state, { cal: target })}" aria-label="${dir === "◀" ? "earlier" : "later"} months">${dir}</a>` : `<span class="nav"></span>`)
    return `<div class="mon"><div class="head">${prev === null ? `<span class="nav"></span>` : nav("◀", prev, addMonths(left, -1))}<span>${MONTHS[Number(ym.slice(5)) - 1]} ${ym.slice(0, 4)}</span>${next === null ? `<span class="nav"></span>` : nav("▶", next, addMonths(left, 1))}</div><table><tr>${DOW.map((d) => `<th>${d.slice(0, 2)}</th>`).join("")}</tr>${weeks}</table></div>`
  }
  const right = addMonths(left, 1)
  const hint = picking === "to" ? `Pick the last day, from ${escapeHtml(from)}` : "Pick the first day"
  return `<section class="card"><p class="cap">Custom range · ${hint} · <a href="${hrefFor(state, { pick: null, cal: null, ...(picking === "to" && !state.to ? { from: null } : {}) })}">cancel</a></p><div class="cal">${month(left, left > firstMonth, null)}${month(right, null, right < today.slice(0, 7))}</div></section>`
}

// credit: an attribution line the backend owes (the self-hosted server's DB-IP data is CC BY 4.0)
// land: the map's outline (LAND from src/world.js); without it there is no map
export function render(model, { days, host, filters = {}, generated, config, cache = "cached up to 5 min", credit = "", land = "", today = new Date().toISOString().slice(0, 10) }) {
  const state = { days, host, ...filters }
  // the window's days, and its hour buckets ("YYYY-MM-DD HH", every step hours) for requests
  const dayWindow = filters.day
    ? [filters.day]
    : filters.from && filters.to
      ? Array.from({ length: spanDays(days, filters) }, (_, i) => addDays(filters.from, i))
      : windowDays(days, today)
  const step = stepHours(days, filters)
  const window = dayWindow.flatMap((d) => Array.from({ length: 24 / step }, (_, i) => `${d} ${String(i * step).padStart(2, "0")}`))
  const c = combine(model, config, host)
  // 1d, 7d, 31d drop any custom range; custom opens the calendar (showing the range when there is one)
  const custom = Boolean(filters.from && filters.to)
  const clear = { day: null, from: null, to: null, pick: null, cal: null }
  const rangeLabel = custom ? (filters.from === filters.to ? filters.from.slice(5) : `${filters.from.slice(5)} – ${filters.to.slice(5)}`) : "custom"
  const dayLinks = [1, 7, 31].map((d) => d === days && !filters.day && !custom && !filters.pick ? `<b aria-current="true">${d}d</b>` : `<a href="${hrefFor(state, { days: d, ...clear })}">${d}d</a>`).join("")
    + (custom || filters.pick ? `<b aria-current="true"><a href="${hrefFor(state, { pick: "from", cal: null, day: null })}">${escapeHtml(rangeLabel)}</a></b>` : `<a href="${hrefFor(state, { pick: "from", cal: null, day: null })}">custom</a>`)
  const sink = filters.view === "sink"
  const viewLinks = sink ? `<a href="${hrefFor(state, { view: null })}">traffic</a><b aria-current="true">sinkhole</b>` : `<b aria-current="true">traffic</b><a href="${hrefFor(state, { view: "sink" })}">sinkhole</a>`
  // every service seen in the window, busiest first; a chip adds its service to the selection or
  // takes it out, so one or several can be in view
  const selected = host ? host.split(",") : []
  const seen = new Map()
  for (const [h, n] of model.hosts || []) seen.set(serviceOf(h, config), (seen.get(serviceOf(h, config)) || 0) + n)
  // a result set without the hosts query (an older backend) still lists what it has
  for (const h of model) if (!seen.has(serviceOf(h.host, config))) seen.set(serviceOf(h.host, config), h.requests)
  // a selected name with no traffic still gets its chip; a selected domain gets its group below
  for (const name of selected) if (!name.startsWith("*.") && !seen.has(name)) seen.set(name, 0)
  const toggle = (name) => {
    const next = selected.includes(name) ? selected.filter((x) => x !== name) : [...selected, name]
    return hrefFor(state, { host: next.join(",") || null })
  }
  const chip = (name, label = name.endsWith("!") ? `${name.slice(0, -1)} only` : name) => {
    const title = config.services[name] ? ` title="${escapeHtml(config.services[name])}"` : ""
    if (selected.includes(name)) return `<a class="sel" href="${toggle(name)}"${title} aria-current="true">${escapeHtml(label)} ×</a>`
    // a full selection takes no more: the 21st name would be dropped
    if (selected.length >= MAX_HOSTS) return `<span class="off" title="at most ${MAX_HOSTS} at a time">${escapeHtml(label)}</span>`
    return `<a href="${toggle(name)}"${title}>${escapeHtml(label)}</a>`
  }
  // services grouped under their domain, the busiest domain first: the domain's chip selects all of
  // it, then a chip per service, named short ("blog" for blog.example.com, "@" for the domain itself)
  const groups = new Map()
  for (const [name, n] of seen) {
    const d = domainOf(name.replace(/!$/, ""))
    const g = groups.get(d) || { n: 0, names: [] }
    g.n += n
    g.names.push([name, n])
    groups.set(d, g)
  }
  for (const item of selected) if (item.startsWith("*.") && !groups.has(item.slice(2))) groups.set(item.slice(2), { n: 0, names: [] })
  const shortName = (name, d) => {
    const bare = name.replace(/!$/, "")
    const label = bare === d ? "@" : bare.endsWith(`.${d}`) ? bare.slice(0, -d.length - 1) : bare
    return name.endsWith("!") ? `${label} only` : label
  }
  const hostLinks = [host ? `<a href="${hrefFor(state, { host: null })}">all</a>` : `<b aria-current="true">all</b>`, ...[...groups].sort((a, b) => b[1].n - a[1].n).map(([d, g]) => {
    const names = g.names.sort((a, b) => b[1] - a[1])
    return `<span class="dom">${chip(`*.${d}`, d)}${names.map(([name]) => chip(name, shortName(name, d))).join("")}</span>`
  })].join("")
  const named = { class: classLabel }
  const active = FILTER_KEYS.filter((k) => filters[k] && k !== "view" && !RANGE_KEYS.includes(k)).map((k) => `<a href="${hrefFor(state, { [k]: null })}" title="remove this filter">${escapeHtml(k)}: ${escapeHtml(named[k] ? named[k](filters[k]) : filters[k])} ×</a>`).join("")
  const ai = [...c.classes].filter(([id]) => id.startsWith("ai-")).reduce((t, [, n]) => t + n, 0)
  const share = c.ok2xx ? Math.round((c.bots / c.ok2xx) * 100) : 0
  const span = filters.day ? escapeHtml(filters.day) : custom ? `${escapeHtml(filters.from)} – ${escapeHtml(filters.to)}` : `last ${days} day${days === 1 ? "" : "s"}`
  const people = [...c.services.values()].filter((s) => s.pageviews).length
  const map = worldMap(c.places, land, state)
  const heat = heatmap(model.heat || [])
  const picked = filters.city ? `${filters.city}, ${filters.country}` : filters.country || ""
  const mapCard = map ? `<div class="card"><p class="cap">${sink ? "Sinkhole traffic" : filters.class && filters.class !== "human" ? escapeHtml(classLabel(filters.class)) : "Visitors"} by city${picked ? ` · ${escapeHtml(picked)} · <a href="${hrefFor(state, { country: null, city: null })}">whole world</a>` : ""} <span class="hint">· scroll to zoom, drag to move</span></p>${map}</div>` : ""
  const tiles = `<div class="tiles">
<div class="tile"><div class="l">Requests</div><div class="v">${fmt(c.requests)}</div><div class="s">${span}</div></div>
${filters.class && filters.class !== "human"
    ? `<div class="tile"><div class="l">Page views</div><div class="v">${fmt(c.pageviews)}</div><div class="s">by ${escapeHtml(classLabel(filters.class))}</div></div>`
    : `<div class="tile"><div class="l">Human page views</div><div class="v">${fmt(c.pageviews)}</div><div class="s">bots and assets excluded</div></div>`}
<div class="tile"><div class="l">Unique visitors</div><div class="v">${fmt(c.visitors)}</div><div class="s">people, counted per day</div></div>
<div class="tile"><div class="l">Bot share</div><div class="v">${shareText(share, model.partial)}</div><div class="s">${model.partial ? "upper bound: the detail query hit its cap" : `${share}% of 2xx from bots`}</div></div>
<div class="tile"><div class="l">AI requests</div><div class="v">${fmt(ai)}</div><div class="s"><a href="${hrefFor(state, { class: "ai-user" })}">assistants</a> · <a href="${hrefFor(state, { class: "ai-search" })}">search</a> · <a href="${hrefFor(state, { class: "ai-training" })}">training</a></div></div>
<div class="tile"><div class="l">Services</div><div class="v">${c.services.size}</div><div class="s">${people} with human traffic</div></div>
</div>`
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escapeHtml(config.title)}</title>
<style>
${CSS}
</style></head><body>
<div class="top"><h1>${escapeHtml(config.title)}</h1>
<p class="muted">${c.requests} requests · ${span}${host ? ` · ${escapeHtml(host.split(",").join(", "))}` : ""} · generated ${escapeHtml(generated)}${cache ? ` · ${escapeHtml(cache)}` : ""}</p></div>
<nav class="bar" aria-label="filters"><div class="seg" aria-label="days">${dayLinks}</div><div class="seg" aria-label="view">${viewLinks}</div><div class="chips" aria-label="services">${hostLinks}</div>${active ? `<div class="chips on" aria-label="active filters">${active}</div>` : ""}</nav>
${filters.pick ? calendar(state, today) : ""}
${model.partial ? `<p class="note">Breakdowns are partial: the detail query hit its ${OK_LIMIT}-group cap, so human counts are a lower bound.</p>` : ""}
${sink ? sinkSection(model, state) : ""}
${model.length ? `${tiles}
${mapCard}
${heat ? `<div class="card"><p class="cap">Requests by weekday and hour (UTC)</p>${heat}</div>` : ""}
${combinedSection(c, window, dayWindow, config, model.partial, state)}` : `<p class="empty muted">No data in this window.</p>`}
${credit ? `<p class="muted foot">${credit}</p>` : ""}
${map ? `<script>${MAP_SCRIPT}</script>` : ""}
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
