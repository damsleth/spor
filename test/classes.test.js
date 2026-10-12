import { test } from "node:test"
import assert from "node:assert/strict"
import { DatabaseSync } from "node:sqlite"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { CLASSES, CLASS_IDS, classOf, classSql, agentName, parseFilters, queries, build, render, toJSON } from "../src/report.js"
import { openStore, HOUR } from "../src/store.js"
import { config } from "./fixture-config.js"

const chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
// real user agents from Analytics Engine, and the edge cases between classes
const ROWS = [
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", bot: "", asorg: "", want: "ai-training", name: "ClaudeBot" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claudebot@anthropic.com)", bot: "", asorg: "", want: "ai-user", name: "Claude-User" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +claudebot@anthropic.com)", bot: "", asorg: "", want: "ai-search", name: "Claude-SearchBot" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", bot: "", asorg: "", want: "ai-user", name: "ChatGPT-User" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot", bot: "AI Crawler", asorg: "Microsoft Corporation", want: "ai-training", name: "GPTBot" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot", bot: "", asorg: "", want: "ai-search", name: "OAI-SearchBot" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", bot: "", asorg: "", want: "ai-search", name: "PerplexityBot" },
  { ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)", bot: "", asorg: "", want: "ai-user", name: "Perplexity-User" },
  { ua: "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) AppleWebKit/537.36", bot: "", asorg: "", want: "ai-training", name: "Bytespider" },
  { ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", bot: "", asorg: "Google LLC", want: "search", name: "Googlebot" },
  { ua: "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", bot: "", asorg: "", want: "preview", name: "facebookexternalhit" },
  { ua: "Mozilla/5.0 zgrab/0.x", bot: "", asorg: "DigitalOcean, LLC", want: "scanner", name: "zgrab" },
  { ua: "curl/8.7.1", bot: "", asorg: "", want: "tool", name: "curl" },
  { ua: "", bot: "", asorg: "", want: "bot", name: "no user agent" },
  { ua: chrome, bot: "Monitoring & Analytics", asorg: "", want: "monitor", name: "Monitoring & Analytics" },
  { ua: chrome, bot: "Archiver", asorg: "", want: "bot", name: "Archiver" },
  { ua: "Mozilla/5.0 (compatible; SomeNewCrawler/2.0)", bot: "", asorg: "", want: "bot", name: "SomeNewCrawler" },
  { ua: chrome, bot: "", asorg: "Hetzner Online GmbH", want: "cloud", name: "Hetzner Online GmbH" },
  { ua: chrome, bot: "", asorg: "Cloudflare, Inc.", want: "human", name: "" },
  { ua: chrome, bot: "", asorg: "Telenor Norge AS", want: "human", name: "" },
  { ua: "Mozilla/5.0 (Linux; Android 14; CUBOT P80) Chrome/140.0 Mobile", bot: "", asorg: "", want: "bot", name: "CUBOT" }
]

test("classOf sorts real user agents into the right class, the narrow AI classes first", () => {
  for (const r of ROWS) {
    assert.equal(classOf(r), r.want, r.ua || r.bot || "(empty)")
    assert.equal(agentName(r), r.name, r.ua || r.bot || "(empty)")
  }
})

test("classSql selects exactly the rows classOf assigns, in SQLite", () => {
  const db = new DatabaseSync(":memory:")
  db.exec("CREATE TABLE t (id INTEGER, ua TEXT, bot TEXT, asorg TEXT)")
  const add = db.prepare("INSERT INTO t VALUES (?, ?, ?, ?)")
  ROWS.forEach((r, i) => add.run(i, r.ua, r.bot, r.asorg))
  const col = { ua: "ua", bot: "bot", asorg: "asorg" }
  for (const id of CLASS_IDS) {
    const got = db.prepare(`SELECT id FROM t WHERE ${classSql(id, col)} ORDER BY id`).all().map((r) => r.id)
    const want = ROWS.map((r, i) => [i, classOf(r)]).filter(([, c]) => c === id).map(([i]) => i)
    assert.deepEqual(got, want, id)
  }
})

test("every class token is a safe SQL literal and LIKE pattern", () => {
  for (const c of CLASSES) for (const t of [...(c.ua || []), ...(c.asorg || []), ...(c.cat || [])]) assert.match(t, /^[A-Za-z0-9 ./&-]+$/, t)
})

test("filters: only values that match their pattern survive, so nothing hostile reaches AE SQL", () => {
  const now = Date.parse("2026-10-12T12:00:00Z")
  const f = (q) => parseFilters(new URLSearchParams(q), now)
  assert.deepEqual(f("country=NO&asn=2119&class=ai-user&path=/a/b.html&ip=203.0.113.7&day=2026-10-10"), { day: "2026-10-10", country: "NO", asn: "2119", class: "ai-user", path: "/a/b.html", ip: "203.0.113.7" })
  assert.deepEqual(f("ip=2001:DB8::1"), { ip: "2001:db8::1" })
  for (const bad of ["country=no", "country=NOR", "country=N'", "asn=12a", "asn=' OR 1", "class=robots", "path=a", "path=/it's", "path=/a\\b", "path=/a b", `path=/${"x".repeat(64)}`, "ip=1.2.3.4' --", "ip=300.1.1.1", "ip=1.2.3", "ip=1::2::3", "ip=::::", "ip=1:2", "day=2026-13-01", "day=2026-02-30", "day=2026-10-13", "day=2026-01-01", "day=yesterday"]) {
    assert.deepEqual(f(bad), {}, bad)
  }
  const sql = Object.values(queries(7, null, config, now, { country: "NO", path: "/x", class: "ai-user", ip: "' OR 1=1 --" })).join("\n")
  assert.match(sql, /blob4 = 'NO'/)
  assert.match(sql, /blob1 = '\/x'/)
  assert.match(sql, /lower\(blob3\) LIKE '%chatgpt-user%'/)
  assert.doesNotMatch(sql, /OR 1=1/)
})

test("a day filter turns the window into that day, by the hour", () => {
  const now = Date.parse("2026-10-12T12:00:00Z")
  const q = queries(31, null, config, now, { day: "2026-10-10" })
  assert.match(q.totals, /timestamp >= toDateTime\('2026-10-10 00:00:00'\) AND timestamp < toDateTime\('2026-10-11 00:00:00'\)/)
  assert.match(q.daily, /INTERVAL '1' HOUR/)
  assert.match(queries(7, null, config, now).daily, /INTERVAL '1' DAY/)
  assert.match(queries(1, null, config, now).daily, /INTERVAL '1' HOUR/)
})

const STORE_NOW = Date.parse("2026-10-06T12:30:00Z")
const H = Math.floor(STORE_NOW / 1000 / HOUR) * HOUR
const point = (over) => ({ hour: H, host: "blog.example.com", path: "/", referer: "", ua: chrome, country: "NO", status: "200", bot: "", origin: "", method: "GET", city: "Oslo", region: "Oslo", asn: "2119", asorg: "Telenor Norge AS", visitor: "aaaaaaaaaaaaaaaa", ip: "203.0.113.7", n: 1, ...over })

function seeded() {
  const s = openStore()
  s.replaceAE(H - 2 * 86400, H + 86400, [
    point({ n: 3 }),
    point({ visitor: "bbbbbbbbbbbbbbbb", ip: "203.0.113.8", path: "/about", n: 2 }),
    point({ hour: H - 86400, visitor: "aaaaaaaaaaaaaaaa", n: 1 }),
    point({ ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot", visitor: "cccccccccccccccc", country: "US", city: "Boydton", region: "Virginia", asn: "8075", asorg: "Microsoft Corporation", ip: "20.1.2.3", n: 5 }),
    point({ ua: "Mozilla/5.0 zgrab/0.x", path: "/.env", status: "404", visitor: "", country: "SG", city: "", asn: "14061", asorg: "DigitalOcean, LLC", ip: "128.199.1.1", n: 7 })
  ])
  return s
}

test("store: visitors per day, cities, networks, agents, IPs and the heatmap", () => {
  const r = seeded().rows(7, null, config, STORE_NOW)
  const model = build(r, config)
  const blog = toJSON(model, config, { days: 7 }).hosts[0]
  assert.equal(blog.visitors, 3, "two people today, one yesterday; the crawler is not a visitor")
  assert.deepEqual(blog.cities, [["Oslo, Oslo, NO", 6]])
  assert.deepEqual(blog.networks, [["2119", "Telenor Norge AS", 6], ["14061", "DigitalOcean, LLC", 7], ["8075", "Microsoft Corporation", 5]].sort((a, b) => b[2] - a[2]))
  assert.deepEqual(blog.classes, [["scanner", 7], ["ai-training", 5]])
  assert.deepEqual(blog.agents, [["scanner", "zgrab", 7], ["ai-training", "GPTBot", 5]])
  assert.deepEqual(blog.ips[0], ["128.199.1.1", "SG · DigitalOcean, LLC", 7])
  // 2026-10-06 is a Tuesday (2); 12:00 UTC
  assert.equal(model.heat[1][12], 17)
  assert.equal(model.heat[0][12], 1)
})

test("store: filters narrow every result set, and a class filter replaces the people-only default", () => {
  const s = seeded()
  const ai = toJSON(build(s.rows(7, null, config, STORE_NOW, { class: "ai-training" }), config), config).hosts[0]
  assert.equal(ai.requests, 5)
  assert.deepEqual(ai.cities, [["Boydton, Virginia, US", 5]])
  assert.equal(ai.visitors, 1)
  const ip = toJSON(build(s.rows(7, null, config, STORE_NOW, { ip: "203.0.113.8" }), config), config).hosts[0]
  assert.equal(ip.requests, 2)
  assert.deepEqual(ip.pages, [["/about", 2]])
  const day = s.rows(31, null, config, STORE_NOW, { day: "2026-10-05" })
  assert.deepEqual(day.daily.map((x) => x.day), ["2026-10-05 12:00:00"])
  assert.equal(day.totals.reduce((t, x) => t + x.n, 0), 1)
})

test("render: every drill-down is a link that keeps the other filters, and active filters can be removed", () => {
  const s = seeded()
  const filters = { country: "NO" }
  const model = build(s.rows(7, "blog.example.com", config, STORE_NOW, filters), config)
  const html = render(model, { days: 7, host: "blog.example.com", filters, config, generated: "x", today: "2026-10-06" })
  assert.match(html, /href="\?days=7&amp;host=blog\.example\.com&amp;country=NO&amp;path=%2Fabout"/)
  assert.match(html, /href="\?days=7&amp;host=blog\.example\.com&amp;country=NO&amp;asn=2119"/)
  assert.match(html, /href="\?days=7&amp;host=blog\.example\.com"[^>]*>country: NO ×/)
  assert.match(html, /<a href="\?days=7&amp;host=blog\.example\.com&amp;day=2026-10-06&amp;country=NO"><g class="pt">/)
  assert.match(html, /class="heat"/)
  assert.match(html, /Unique visitors/)
})

test("an old store gains the new columns and keeps its rows", () => {
  const file = join(mkdtempSync(join(tmpdir(), "spor-store-")), "old.db")
  const old = new DatabaseSync(file)
  const v1 = ["host", "path", "referer", "ua", "country", "status", "bot", "origin", "method"]
  old.exec(`CREATE TABLE hits (hour INTEGER NOT NULL, ${v1.map((f) => `${f} TEXT NOT NULL`).join(", ")}, source TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (hour, ${v1.join(", ")}, source)) WITHOUT ROWID;
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO hits VALUES (3600, 'blog.example.com', '/', '', 'x', 'NO', '200', '', '', 'GET', 'ae', 4);
INSERT INTO meta VALUES ('ae:synced', '0');`)
  old.close()
  const s = openStore(file)
  assert.deepEqual({ ...s.db.prepare("SELECT host, n, city, ip FROM hits").get() }, { host: "blog.example.com", n: 4, city: "", ip: "" })
  assert.equal(s.meta("ae:synced"), "0")
  s.addLocal({ host: "app.example.net", path: "/", ip: "203.0.113.7" }, "nginx", 7200)
  assert.equal(s.db.prepare("SELECT ip FROM hits WHERE host = 'app.example.net'").get().ip, "203.0.113.7")
  s.close()
  assert.equal(openStore(file).db.prepare("SELECT COUNT(*) AS c FROM hits").get().c, 2, "opening again leaves it alone")
})

test("a tab in a network name keeps the agents tuple at [class, name, count]", () => {
  const model = build({ agents: [{ host: "blog.example.com", ua: chrome, bot: "", asorg: "Amazon\tNetwork", n: 2 }] }, config)
  assert.deepEqual(toJSON(model, config).hosts[0].agents, [["cloud", "Amazon\tNetwork", 2]])
})

test("aliases fold into their service; a selection covers a service's names and trailing dots", async () => {
  const { loadConfig, selectedHosts, validHost } = await import("../src/report.js")
  const cfg = loadConfig({ services: { "example.com": "site", "blog.example.com": "blog" }, aliases: { "www.example.com": "example.com", "Example.NET": "example.com" } })
  assert.deepEqual(selectedHosts("example.com", cfg).sort(), ["example.com", "example.com.", "example.net", "example.net.", "www.example.com", "www.example.com."])
  assert.deepEqual(selectedHosts("www.example.com", cfg), ["www.example.com", "www.example.com."], "an alias alone is just that name")
  assert.equal(validHost("example.com,blog.example.com", cfg), "example.com,blog.example.com")
  for (const bad of [{ "a.example": "a.example" }, { "a.example": "b.example", "b.example": "c.example" }, { "x'y": "a.example" }]) {
    assert.throws(() => loadConfig({ aliases: bad }), /config\.aliases/, JSON.stringify(bad))
  }
  const q = queries(7, "example.com", cfg)
  assert.match(q.totals, /index1 IN \('example\.com', 'example\.com\.', 'www\.example\.com', 'www\.example\.com\.', 'example\.net', 'example\.net\.'\)/)
})

test("the combined view sums services, names their hosts, and chips toggle a selection", async () => {
  const { loadConfig } = await import("../src/report.js")
  const cfg = loadConfig({ services: { "example.com": "site", "blog.example.com": "blog" }, aliases: { "www.example.com": "example.com" } })
  const rows = {
    totals: [{ host: "example.com", status: "200", n: 5 }, { host: "www.example.com", status: "200", n: 3 }, { host: "example.com.", status: "200", n: 1 }, { host: "blog.example.com", status: "200", n: 2 }],
    ok: [{ host: "example.com", path: "/", ua: chrome, method: "GET", n: 5 }, { host: "blog.example.com", path: "/", ua: chrome, method: "GET", n: 2 }],
    hosts: [{ host: "example.com", n: 6 }, { host: "www.example.com", n: 3 }, { host: "blog.example.com", n: 2 }]
  }
  const model = build(rows, cfg)
  assert.equal(model.find((h) => h.host === "example.com").requests, 6, "the trailing-dot row folds into example.com")
  const all = render(model, { days: 7, host: null, config: cfg, generated: "x" })
  assert.match(all, /example\.com · site<\/a><\/span><\/div><\/td><td class="n">9</, "the service sums its hosts")
  assert.match(all, /blog\.example\.com\/<\/a>/, "with several services, a page row names its service")
  assert.match(all, /href="\?days=7&amp;host=example\.com" title="site">example\.com<\/a>/, "a chip adds its service")
  assert.equal((all.match(/<section class="card">/g) || []).length, 1, "one combined card")
  const one = render(build({ ...rows, totals: rows.totals.slice(0, 3) }, cfg), { days: 7, host: "example.com,blog.example.com", config: cfg, generated: "x" })
  assert.match(one, /class="sel" href="\?days=7&amp;host=blog\.example\.com"[^>]*>example\.com ×/, "a selected chip removes itself")
  assert.match(one, /host names/, "a service with several names lists them")
})

test("the map draws one linked circle per place, from rows with coordinates only", async () => {
  const { LAND } = await import("../src/world.js")
  assert.match(LAND, /^[MLZ0-9 ]+$/, "the outline is only path commands and integers")
  const geo = [
    { host: "blog.example.com", country: "NO", region: "Oslo", city: "Oslo", lat: "59.91", lon: "10.74", n: 4 },
    { host: "blog.example.com", country: "AE", region: "Abu Dhabi", city: "Abu Dhabi", lat: "24.45", lon: "54.38", n: 1 },
    { host: "blog.example.com", country: "US", region: "", city: "Old", lat: "", lon: "", n: 9 }
  ]
  const model = build({ totals: [{ host: "blog.example.com", status: "200", n: 14 }], geo }, config)
  const html = render(model, { days: 7, host: null, config, generated: "x", land: LAND })
  assert.equal((html.match(/<circle cx/g) || []).length, 2, "the row without coordinates has no circle")
  assert.match(html, /<a href="\?days=7&amp;country=NO&amp;city=Oslo"><g class="pt"><circle class="hit" cx="381\.48" cy="48\.18"/, "a circle selects its city")
  assert.match(html, /Oslo, Oslo, NO: 4/)
  assert.doesNotMatch(render(model, { days: 7, host: null, config, generated: "x" }), /class="map"/, "no outline, no map")
  assert.deepEqual(toJSON(model, config).hosts[0].places[0], ["Oslo, Oslo, NO", 59.91, 10.74, 4])
})

test("narrowing never widens: host names select one name, page rows keep the selected item", async () => {
  const { loadConfig, selectedHosts, validHost } = await import("../src/report.js")
  const cfg = loadConfig({ services: { "example.com": "site", "other.example": "other" }, aliases: { "www.example.com": "example.com" }, proxyHosts: ["example.com"] })
  assert.equal(validHost("example.com!,www.example.com", cfg), "example.com!,www.example.com")
  assert.deepEqual(selectedHosts("example.com!", cfg), ["example.com", "example.com."], "name! is that name alone")
  const rows = {
    totals: [{ host: "example.com", status: "200", n: 5 }, { host: "www.example.com", status: "200", n: 3 }, { host: "other.example", status: "200", n: 1 }],
    ok: [{ host: "www.example.com", path: "/a", ua: chrome, method: "GET", n: 3 }, { host: "other.example", path: "/b", ua: chrome, method: "GET", n: 1 }]
  }
  const all = render(build(rows, cfg), { days: 7, host: null, config: cfg, generated: "x" })
  assert.match(all, /href="\?days=7&amp;host=example\.com!">example\.com<\/a>/, "the canonical name's row selects it alone")
  const picked = render(build(rows, cfg), { days: 7, host: "www.example.com,other.example", config: cfg, generated: "x" })
  assert.match(picked, /href="\?days=7&amp;host=www\.example\.com&amp;path=%2Fa"/, "a page row keeps the alias selection")
  const full = Array.from({ length: 20 }, (_, i) => `h${i}.example`).join(",")
  const limit = render(build({ ...rows, hosts: [{ host: "new.example", n: 1 }] }, cfg), { days: 7, host: full, config: cfg, generated: "x" })
  assert.match(limit, /<span class="off" title="at most 20 at a time">new\.example<\/span>/)
})

test("dotted and alias referers are self-referrals, and a proxy's aliases count as the proxy", async () => {
  const { loadConfig } = await import("../src/report.js")
  const cfg = loadConfig({ services: { "example.com": "site" }, aliases: { "www.example.com": "example.com" }, proxyHosts: ["example.com"] })
  const model = build({
    ok: [
      { host: "example.com.", path: "/", referer: "https://example.com.", ua: chrome, method: "GET", n: 1 },
      { host: "example.com", path: "/", referer: "https://www.example.com", ua: chrome, method: "GET", n: 1 },
      { host: "example.com", path: "/", referer: "https://news.example", ua: chrome, method: "GET", n: 1 }
    ],
    paths: [{ host: "example.com", path: "/target.example", status: "200", n: 5 }, { host: "www.example.com", path: "/target.example", status: "200", n: 3 }]
  }, cfg)
  const json = toJSON(model, cfg)
  assert.deepEqual(json.hosts.flatMap((h) => h.referers), [["https://news.example", 1]])
  assert.equal(json.hosts.flatMap((h) => h.targets).reduce((t, [, n]) => t + n, 0), 8)
})

test("map places keep their own name and country, and small circles are drawn last", async () => {
  const { LAND } = await import("../src/world.js")
  const geo = [
    { host: "blog.example.com", country: "AA", region: "", city: "First", lat: "10.00", lon: "20.00", n: 4 },
    { host: "app.example.net", country: "BB", region: "", city: "Second", lat: "10.00", lon: "20.00", n: 3 },
    { host: "blog.example.com", country: "NO", region: "", city: "Big", lat: "47.60", lon: "7.60", n: 100 },
    { host: "blog.example.com", country: "CH", region: "", city: "Small", lat: "47.60", lon: "7.59", n: 1 }
  ]
  const model = build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }], geo }, config)
  const html = render(model, { days: 7, host: null, config, generated: "x", land: LAND })
  assert.match(html, /country=AA&amp;city=First"><g class="pt">[^]*?<title>First, AA: 4/)
  assert.match(html, /country=BB&amp;city=Second"><g class="pt">[^]*?<title>Second, BB: 3/)
  assert.ok(html.indexOf("Big, NO") < html.indexOf("Small, CH"), "the smaller circle comes later, on top")
})

test("a selected place is orange, drawn last, zoomed to, and a click elsewhere drops it", async () => {
  const { LAND } = await import("../src/world.js")
  const places = [
    { host: "blog.example.com", country: "NO", region: "Oslo", city: "Oslo", lat: "59.91", lon: "10.74", n: 4 },
    { host: "blog.example.com", country: "NO", region: "Vestland", city: "Bergen", lat: "60.39", lon: "5.32", n: 2 },
    { host: "blog.example.com", country: "US", region: "", city: "Ashburn", lat: "39.04", lon: "-77.49", n: 50 }
  ]
  const filters = { country: "NO", city: "Oslo" }
  const model = build({ totals: [{ host: "blog.example.com", status: "200", n: 56 }], geo: [places[0]], places }, config)
  const html = render(model, { days: 7, host: null, filters, config, generated: "x", land: LAND })
  const map = html.slice(html.indexOf('<svg class="map"'), html.indexOf("</svg>", html.indexOf('<svg class="map"')))
  assert.equal((map.match(/<circle cx/g) || []).length, 3, "every place stays on the map")
  assert.equal((map.match(/class="sel"/g) || []).length, 1)
  assert.ok(map.lastIndexOf("Ashburn") < map.lastIndexOf("Oslo, Oslo, NO"), "the selection is drawn last")
  const [x, , w] = /viewBox="([^"]+)"/.exec(map)[1].split(" ").map(Number)
  assert.ok(w < 720 && x > 300, "zoomed onto Norway")
  assert.match(map, /<a href="\?days=7" aria-label="show the whole world"><rect class="sea"/, "a click on the map drops the selection")
  assert.match(map, /<a href="\?days=7"><g class="pt">[^]*?Oslo, Oslo, NO: 4/, "a click on the selected city drops it")
  assert.match(map, /href="\?days=7&amp;country=NO&amp;city=Bergen"/, "another city in view can be picked")
  assert.match(html, /Oslo, NO · <a href="\?days=7">whole world<\/a>/)
})

test("the city filter takes real city names and nothing that could break SQL", () => {
  const f = (q) => parseFilters(new URLSearchParams(q))
  for (const city of ["Oslo", "São Paulo", "Oslo (Nordre Aker District)", "Saint-Étienne", "St. Louis", "Москва", "東京"]) assert.equal(f({ city }).city, city, city)
  for (const city of ["O'Fallon", "a\\b", " Oslo", "x".repeat(65), "Oslo;DROP", "a\tb"]) assert.equal(f({ city }).city, undefined, city)
  const q = queries(7, null, config, Date.now(), { country: "NO", city: "Oslo" })
  assert.match(q.geo, /blob9 = 'Oslo'/)
  assert.doesNotMatch(q.places, /blob9 = 'Oslo'|blob4 = 'NO'/, "the map's places skip the selection")
})

test("resolving many aliases for many selected services stays cheap", async () => {
  const { loadConfig } = await import("../src/report.js")
  const services = {}
  const aliases = {}
  for (let i = 0; i < 20; i++) {
    services[`s${i}.example`] = "x"
    for (let j = 0; j < 15; j++) aliases[`a${j}.s${i}.example`] = `s${i}.example`
  }
  const cfg = loadConfig({ services, aliases })
  const totals = Object.keys(aliases).concat(Object.keys(services)).map((host) => ({ host, status: "200", n: 1 }))
  const host = Object.keys(services).join(",")
  // a ratio, not a wall-clock limit, so a slow CI runner can't fail it: with the selection the page
  // may cost a few times what it costs without one (before the fix it cost about 35 times as much)
  const time = (h) => {
    for (let k = 0; k < 3; k++) render(build({ totals }, cfg), { days: 7, host: h, config: cfg, generated: "x" })
    const t = performance.now()
    for (let k = 0; k < 10; k++) render(build({ totals }, cfg), { days: 7, host: h, config: cfg, generated: "x" })
    return performance.now() - t
  }
  const ratio = time(host) / time(null)
  assert.ok(ratio < 5, `selection costs ${ratio.toFixed(1)}x`)
})

test("the status donut has a slice per code, the rest as other, and survives a single code", async () => {
  const many = build({ totals: ["200", "404", "301", "302", "304", "401", "403", "405", "500", "503"].map((status, i) => ({ host: "blog.example.com", status, n: 100 - i })) }, config)
  const html = render(many, { days: 7, host: null, config, generated: "x" })
  const pie = html.slice(html.indexOf('<svg class="pie"'), html.indexOf("</svg>", html.indexOf('<svg class="pie"')))
  assert.equal((pie.match(/<path /g) || []).length, 9, "8 codes and other")
  assert.match(pie, /<title>other: 183 \(/)
  const one = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 5 }] }, config), { days: 7, host: null, config, generated: "x" })
  assert.match(one, /<path class="c2" d="M[^"]+A[^"]+A[^"]+M/, "a whole circle is drawn as two halves")
})

test("every chart label is escaped, and heatmap cells carry their hover label", () => {
  const model = build({ totals: [{ host: "blog.example.com", status: "<b>", n: 3 }], heat: [{ dow: 1, hr: 9, n: 3 }] }, config)
  const html = render(model, { days: 7, host: null, config, generated: "x" })
  const pie = html.slice(html.indexOf('<svg class="pie"'), html.indexOf("</svg>", html.indexOf('<svg class="pie"')))
  assert.doesNotMatch(pie, /<b>/)
  assert.match(pie, /&lt;b&gt;/)
  assert.match(html, /<title>Mon 09:00 UTC: 3 requests<\/title>/)
  assert.match(html, /<g class="tip">[^]*?Mon 09:00 UTC: 3 requests<\/text>/)
})
