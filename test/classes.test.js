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
  assert.match(queries(7, null, config, now).daily, /INTERVAL '1' HOUR/, "a week by the hour")
  assert.match(queries(31, null, config, now).daily, /INTERVAL '6' HOUR/, "a month by 6 hours")
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
  assert.match(html, /<a href="\?days=7&amp;host=blog\.example\.com&amp;day=2026-10-06&amp;country=NO"><g class="pt" aria-label=/)
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
  assert.match(all, /href="\?days=7&amp;host=example\.com" title="site">@<\/a>/, "a chip adds its service (@: the domain's own)")
  assert.match(all, /<span class="dom"><a href="\?days=7&amp;host=\*\.example\.com">example\.com<\/a>/, "the domain's chip selects all of it")
  assert.equal((all.match(/<section class="card">/g) || []).length, 1, "one combined card")
  const one = render(build({ ...rows, totals: rows.totals.slice(0, 3) }, cfg), { days: 7, host: "example.com,blog.example.com", config: cfg, generated: "x" })
  assert.match(one, /class="sel" href="\?days=7&amp;host=blog\.example\.com"[^>]*>@ ×/, "a selected chip removes itself")
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
  assert.match(html, /<a href="\?days=7&amp;country=NO&amp;city=Oslo"><g class="pt" aria-label="Oslo, Oslo, NO: 4"><circle class="hit" cx="381\.48" cy="48\.18"/, "a circle selects its city")
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
  assert.match(html, /country=AA&amp;city=First"><g class="pt" aria-label="First, AA: 4"/)
  assert.match(html, /country=BB&amp;city=Second"><g class="pt" aria-label="Second, BB: 3"/)
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
  assert.match(map, /<a href="\?days=7" aria-label="show the whole world"><rect class="sea" x="0" y="0" width="720" height="288"/, "a click anywhere on the map drops the selection")
  assert.match(map, /<a href="\?days=7"><g class="pt" aria-label="Oslo, Oslo, NO: 4"/, "a click on the selected city drops it")
  assert.match(map, /href="\?days=7&amp;country=NO&amp;city=Bergen"/, "another city in view can be picked")
  assert.match(html, /Oslo, NO · <a href="\?days=7">whole world<\/a>/)
})

test("the city filter takes real city names and nothing that could break SQL", () => {
  const f = (q) => parseFilters(new URLSearchParams(q))
  for (const city of ["Oslo", "São Paulo", "Oslo (Nordre Aker District)", "Saint-Étienne", "St. Louis", "Москва", "東京"]) assert.equal(f({ city }).city, city, city)
  for (const city of ["O'Fallon", "a\\b", " Oslo", "x".repeat(65), "Oslo;DROP", "a\tb"]) assert.equal(f({ city }).city, undefined, city)
  const q = queries(7, null, config, Date.now(), { country: "NO", city: "Oslo" })
  assert.match(q.geo, /blob9 = 'Oslo'/)
  assert.doesNotMatch(q.places.slice(q.places.indexOf(" FROM ")), /blob9 = 'Oslo'|blob4 = 'NO'/, "the map's places don't filter on the selection (they only sort it first)")
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
  assert.match(pie, /aria-label="other: 183 \(/)
  const one = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 5 }] }, config), { days: 7, host: null, config, generated: "x" })
  assert.match(one, /<path d="M[^"]+A[^"]+A[^"]+M[^"]+" fill-rule="evenodd" style="fill:#2e9e63"/, "a whole circle is drawn as two halves")
  // four 4xx codes: four different colors, the legend matching the slices
  const fours = render(build({ totals: ["404", "400", "401", "403"].map((status, i) => ({ host: "blog.example.com", status, n: 10 - i })) }, config), { days: 7, host: null, config, generated: "x" })
  const fills = [...fours.matchAll(/style="fill:(#[0-9a-f]{6})"/g)].map((m) => m[1])
  assert.equal(new Set(fills).size, 4)
  // eight codes of one class, the donut's full eight slices: eight colors
  const twos = render(build({ totals: ["200", "201", "202", "204", "206", "207", "208", "226"].map((status, i) => ({ host: "blog.example.com", status, n: 20 - i })) }, config), { days: 7, host: null, config, generated: "x" })
  assert.equal(new Set([...twos.matchAll(/style="fill:(#[0-9a-f]{6})"/g)].map((m) => m[1])).size, 8)
  // eight unusual codes and other: nine slices, nine colors
  const odd = render(build({ totals: Array.from({ length: 9 }, (_, i) => ({ host: "blog.example.com", status: String(100 + i), n: 20 - i })) }, config), { days: 7, host: null, config, generated: "x" })
  assert.equal(new Set([...odd.matchAll(/style="fill:(#[0-9a-f]{6})"/g)].map((m) => m[1])).size, 9)
  assert.deepEqual([...fours.matchAll(/<i style="background:(#[0-9a-f]{6})">/g)].map((m) => m[1]), fills)
})

test("every chart label is escaped, and heatmap cells carry their hover label", () => {
  const model = build({ totals: [{ host: "blog.example.com", status: "<b>", n: 3 }], heat: [{ dow: 1, hr: 9, n: 3 }] }, config)
  const html = render(model, { days: 7, host: null, config, generated: "x" })
  const pie = html.slice(html.indexOf('<svg class="pie"'), html.indexOf("</svg>", html.indexOf('<svg class="pie"')))
  assert.doesNotMatch(pie, /<b>/)
  assert.match(pie, /&lt;b&gt;/)
  assert.match(html, /<g class="pt" aria-label="Mon 09:00 UTC: 3 requests">/)
  assert.doesNotMatch(html.slice(html.indexOf('<svg class="heat"')), /<title>/, "no native tooltip next to the hover label")
  assert.match(html, /<g class="tip">[^]*?Mon 09:00 UTC: 3 requests<\/text>/)
})

test("every line chart hit area stays inside the plot, edge to edge without gaps", () => {
  for (const days of [1, 3, 7, 31]) {
    const daily = Array.from({ length: days }, (_, i) => ({ day: `2026-10-${String(12 - days + 1 + i).padStart(2, "0")} 00:00:00`, host: "blog.example.com", n: i + 1 }))
    const html = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }], daily }, config, { hourly: days === 1 }), { days, host: null, config, generated: "x", today: "2026-10-12" })
    const chart = html.slice(html.indexOf('<svg class="line"'), html.indexOf("</svg>", html.indexOf('<svg class="line"')))
    const hits = [...chart.matchAll(/<rect class="hit" x="([\d.]+)" y="[\d.]+" width="([\d.]+)"/g)].map((m) => [Number(m[1]), Number(m[1]) + Number(m[2])])
    assert.equal(hits.length, days <= 7 ? days * 24 : days * 4, `${days} days`)
    assert.equal(hits[0][0], 40)
    assert.ok(Math.abs(hits.at(-1)[1] - 710) < 0.2, `${days} days: last ends at the plot's edge`)
    for (let i = 1; i < hits.length; i++) assert.ok(Math.abs(hits[i][0] - hits[i - 1][1]) < 0.2, `${days} days: no gap or overlap at ${i}`)
  }
})

test("map places outside the filters add no host, country links drop the city, and the cap keeps the selection", async () => {
  const { LAND } = await import("../src/world.js")
  const place = (host, country, city, lat, lon, n) => ({ host, country, region: "", city, lat, lon, n })
  const filters = { country: "NO", city: "Oslo" }
  const model = build({
    totals: [{ host: "blog.example.com", status: "200", n: 4 }],
    ok: [{ host: "blog.example.com", path: "/", ua: chrome, country: "NO", method: "GET", n: 4 }],
    places: [place("blog.example.com", "NO", "Oslo", "59.91", "10.74", 4), place("app.example.net", "US", "Ashburn", "39.04", "-77.49", 50)]
  }, config)
  assert.deepEqual(model.map((h) => h.host), ["blog.example.com"], "Ashburn's host is not in the report")
  const html = render(model, { days: 7, host: null, filters, config, generated: "x", land: LAND })
  assert.match(html, /Ashburn/, "but Ashburn is on the map")
  assert.match(html, /<a href="\?days=7&amp;country=NO">NO<\/a>/, "a country link drops the city")
  const empty = build({ places: [place("app.example.net", "US", "Ashburn", "39.04", "-77.49", 50)] }, config)
  assert.match(render(empty, { days: 7, host: null, filters, config, generated: "x", land: LAND }), /No data in this window/)
  const many = Array.from({ length: 301 }, (_, i) => place("blog.example.com", i === 300 ? "NO" : "US", i === 300 ? "Oslo" : `C${i}`, "10.00", String(-170 + i), i === 300 ? 1 : 100))
  const capped = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }], places: many }, config), { days: 7, host: null, filters, config, generated: "x", land: LAND })
  assert.match(capped, /class="sel"/, "the selected place makes the map though it is the 301st")
  assert.equal((capped.match(/<circle cx/g) || []).length, 300)
})

test("a quiet selected city survives the SQL cap, the frame covers every selected place, and API places keep their own label", async () => {
  const { LAND } = await import("../src/world.js")
  const s = openStore()
  const now = Date.parse("2026-10-06T12:30:00Z")
  const h = Math.floor(now / 1000 / HOUR) * HOUR
  const row = (city, country, lon, n) => ({ hour: h, host: "blog.example.com", path: "/", ua: chrome, country, status: "200", city, region: "", lat: "40.00", lon: String(lon), n })
  s.replaceAE(h - HOUR, h + HOUR, [...Array.from({ length: 500 }, (_, i) => row(`C${i}`, "US", -100 + i * 0.01, 100)), row("Oslo", "NO", 10.74, 1)])
  const rows = s.rows(7, null, config, now, { country: "NO", city: "Oslo" })
  assert.equal(rows.places.length, 500)
  assert.equal(rows.places[0].city, "Oslo", "the selection sorts first, inside the LIMIT")
  const q = queries(7, null, config, now, { country: "NO", city: "Oslo" })
  assert.match(q.places, /if\(blob4 = 'NO' AND blob9 = 'Oslo', 1, 0\) AS sel/)
  assert.match(q.places, /ORDER BY sel DESC, n DESC/)
  // 301 selected places: the quiet one far east still sets the frame
  const places = [...Array.from({ length: 300 }, (_, i) => ({ host: "blog.example.com", country: "US", region: "", city: `C${i}`, lat: "40.00", lon: String(-170 + i * 0.01), n: 100 })), { host: "blog.example.com", country: "US", region: "", city: "Far", lat: "40.00", lon: "170", n: 1 }]
  const html = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }], places }, config), { days: 7, host: null, filters: { country: "US" }, config, generated: "x", land: LAND })
  const [, , w] = /class="map" viewBox="([^"]+)"/.exec(html)[1].split(" ").map(Number)
  assert.ok(w > 600, `the frame spans the far city (${w})`)
  const two = build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }, { host: "app.example.net", status: "200", n: 1 }], places: [
    { host: "blog.example.com", country: "US", region: "Region A", city: "Springfield", lat: "39.80", lon: "-89.64", n: 1 },
    { host: "app.example.net", country: "US", region: "Region B", city: "Springfield", lat: "39.80", lon: "-89.64", n: 1 }
  ] }, config)
  assert.deepEqual(toJSON(two, config).hosts.map((x) => x.places[0][0]).sort(), ["Springfield, Region A, US", "Springfield, Region B, US"])
})

test("the map's script is the only one, allowed by its hash, and only on a page with a map", async () => {
  const { MAP_SCRIPT, MAP_SCRIPT_HASH } = await import("../src/report.js")
  const { HEADERS } = await import("../src/http.js")
  const { createHash } = await import("node:crypto")
  const { LAND } = await import("../src/world.js")
  assert.equal(MAP_SCRIPT_HASH, `sha256-${createHash("sha256").update(MAP_SCRIPT).digest("base64")}`, "MAP_SCRIPT and MAP_SCRIPT_HASH change together")
  assert.match(HEADERS["Content-Security-Policy"], new RegExp(`default-src 'none'; style-src 'unsafe-inline'; script-src '${MAP_SCRIPT_HASH.replace(/[+/=]/g, "\\$&")}';`))
  assert.doesNotMatch(MAP_SCRIPT, /innerHTML|outerHTML|insertAdjacent|eval\(|Function\(|textContent|fetch\(|location/, "it touches no text and no network")
  const geo = [{ host: "blog.example.com", country: "NO", region: "", city: "Oslo", lat: "59.91", lon: "10.74", n: 1 }]
  const withMap = render(build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }], geo }, config), { days: 7, host: null, config, generated: "x", land: LAND })
  assert.equal((withMap.match(/<script>/g) || []).length, 1)
  assert.ok(withMap.includes(`<script>${MAP_SCRIPT}</script>`), "the exact text the hash allows")
  assert.doesNotMatch(render(build({ totals: [{ host: "blog.example.com", status: "200", n: 1 }] }, config), { days: 7, host: null, config, generated: "x" }), /<script/)
})

test("the visitors chart counts distinct visitors per hour, and the total stays per day", () => {
  const s = openStore()
  const now = Date.parse("2026-10-06T12:30:00Z")
  const h = Math.floor(now / 1000 / HOUR) * HOUR
  const v = (hour, visitor) => ({ hour, host: "blog.example.com", path: "/", ua: chrome, status: "200", visitor, n: 1 })
  // one visitor in two hours, a second in one: 2 that day, 1 and 2 by the hour
  s.replaceAE(h - 2 * HOUR, h + HOUR, [v(h - HOUR, "aaaaaaaaaaaaaaaa"), v(h, "aaaaaaaaaaaaaaaa"), v(h, "bbbbbbbbbbbbbbbb")])
  const r = s.rows(1, null, config, now)
  const json = toJSON(build(r, config), config).hosts[0]
  assert.equal(json.visitors, 2)
  assert.deepEqual(json.visitorsHourly, [["2026-10-06 11", 1], ["2026-10-06 12", 2]])
  assert.match(queries(31, null, config, now).visitorsHours, /INTERVAL '6' HOUR/)
  const html = render(build(r, config), { days: 1, host: null, config, generated: "x", today: "2026-10-06" })
  assert.match(html, /aria-label="Tue 10-06 12:00 UTC: 2 visitors"/)
})

test("a domain selection covers the domain and every name under it, in both backends", async () => {
  const { validHost, hostSql, covers, domainOf } = await import("../src/report.js")
  assert.equal(validHost("*.Example.COM.,blog.example.com", config), "*.example.com,blog.example.com")
  for (const bad of ["*.", "**.example.com", "*example.com", "*.exa mple.com", "*.x'y"]) assert.equal(validHost(bad, config), null, bad)
  assert.equal(domainOf("a.b.example.com."), "example.com")
  assert.ok(covers("*.example.com", "example.com", config) && covers("*.example.com", "deep.blog.example.com", config))
  assert.ok(!covers("*.example.com", "notexample.com", config), "a suffix match needs the dot")
  assert.equal(hostSql("*.example.com", config, "index1", (v) => `'${v}'`), " AND (index1 = 'example.com' OR index1 = 'example.com.' OR index1 LIKE '%.example.com' OR index1 LIKE '%.example.com.')")
  const s = openStore()
  const now = Date.parse("2026-10-06T12:30:00Z")
  const h = Math.floor(now / 1000 / HOUR) * HOUR
  const row = (host, n) => ({ hour: h, host, path: "/", ua: chrome, status: "200", n })
  s.replaceAE(h - HOUR, h + HOUR, [row("example.com", 1), row("blog.example.com", 2), row("notexample.com", 4), row("other.net", 8)])
  const model = build(s.rows(1, "*.example.com", config, now), config)
  assert.deepEqual(model.map((x) => [x.host, x.requests]).sort(), [["blog.example.com", 2], ["example.com", 1]])
  const html = render(model, { days: 1, host: "*.example.com", config, generated: "x", today: "2026-10-06" })
  assert.match(html, /<caption>services<\/caption>/, "a domain selection still breaks down by service")
  assert.match(html, /class="sel" href="\?days=1"[^>]*>example\.com ×/, "the domain chip shows it is selected")
  assert.doesNotMatch(html, />\* ×</, "the selection doesn't add a chip of its own")
  const quiet = render(build({ totals: [{ host: "other.net", status: "200", n: 1 }] }, config), { days: 1, host: "*.example.com", config, generated: "x", today: "2026-10-06" })
  assert.match(quiet, /class="sel" href="\?days=1"[^>]*>example\.com ×/, "a selected domain without traffic keeps its chip, to drop it")
})

test("a custom range: real dates within AE's 92 days, swapped if backwards, and its step", async () => {
  const { span, stepHours } = await import("../src/report.js")
  const now = Date.parse("2026-10-12T15:00:00Z")
  const f = (q) => parseFilters(new URLSearchParams(q), now)
  assert.deepEqual(f("from=2026-10-05&to=2026-09-28"), { from: "2026-09-28", to: "2026-10-05" })
  assert.deepEqual(f("from=2026-10-05&pick=to&cal=2026-09"), { from: "2026-10-05", pick: "to", cal: "2026-09" })
  for (const bad of ["from=2026-10-13&to=2026-10-14", "from=2026-07-01&to=2026-07-02", "from=2026-02-30&to=2026-03-01", "from=x' OR 1&to=2026-10-01", "pick=both", "cal=2026-06", "cal=2026-11", "cal=2026-9"]) assert.deepEqual(f(bad), {}, bad)
  assert.deepEqual(span(7, f("from=2026-10-01&to=2026-10-03")), { from: "2026-10-01 00:00:00", to: "2026-10-04 00:00:00", fromSeconds: Date.parse("2026-10-01") / 1000, toSeconds: Date.parse("2026-10-04") / 1000, hourly: false, step: 1 })
  assert.deepEqual([["2026-10-01", "2026-10-07"], ["2026-10-01", "2026-10-08"], ["2026-09-01", "2026-10-01"], ["2026-08-31", "2026-10-01"]].map(([from, to]) => stepHours(7, { from, to })), [1, 6, 6, 24])
  assert.equal(span(1, f("from=2026-10-05&to=2026-10-05")).hourly, true, "a range of one day is that day")
})

test("the calendar picks a range in two clicks, links only days with data, and keeps the range out of the chips", () => {
  const today = "2026-10-12"
  const now = Date.parse("2026-10-12T15:00:00Z")
  const view = (q) => render(build({}, config), { days: 7, filters: parseFilters(new URLSearchParams(q), now), config, generated: "x", today })
  const first = view("pick=from")
  assert.match(first, /September 2026.*October 2026/s, "the month before today's, then today's")
  assert.match(first, /href="\?days=7&amp;from=2026-10-05&amp;pick=to&amp;cal=2026-09">5</, "the first click sets from and asks for to")
  assert.doesNotMatch(first, /from=2026-10-13/, "no days after today")
  assert.match(first, /<td class="out"><span>28<\/span><\/td>/, "the other months' days are gray and not links")
  assert.doesNotMatch(first, /aria-label="later months"/, "nothing after today's month")
  assert.match(first, /aria-label="earlier months"/)
  const second = view("from=2026-10-05&pick=to&cal=2026-09")
  assert.match(second, /<td class="end"><a[^>]*>5</, "from is marked")
  assert.match(second, /href="\?days=7&amp;from=2026-10-05&amp;to=2026-10-08">8</, "a later day ends the range")
  assert.match(second, /href="\?days=7&amp;from=2026-10-01&amp;pick=to&amp;cal=2026-09">1</, "an earlier day starts it again")
  const set = view("from=2026-09-28&to=2026-10-05")
  assert.match(set, /<b aria-current="true"><a href="[^"]*pick=from[^"]*">09-28 – 10-05<\/a><\/b>/, "the segment shows the range, and reopens the calendar")
  assert.match(set, /2026-09-28 – 2026-10-05/)
  assert.doesNotMatch(set, /class="cal"/, "no calendar once picked")
  assert.doesNotMatch(set, /aria-label="active filters"/, "the range is not a filter chip")
  assert.match(set, /href="\?days=7">7d</, "7d drops the range")
  assert.match(view("from=2026-09-28&to=2026-10-05&day=2026-10-01"), /<b aria-current="true"><a href="\?days=7&amp;from=2026-09-28&amp;to=2026-10-05&amp;pick=from">/, "reopening the calendar drops a day drill-down, which would override the new range")
  const feb = Date.parse("2027-02-12T12:00:00Z")
  assert.deepEqual(parseFilters(new URLSearchParams("pick=from&cal=2026-13"), feb), { pick: "from" }, "no month 13, even inside the retention's span of months")
  assert.equal(parseFilters(new URLSearchParams("cal=2026-12"), feb).cal, "2026-12")
})

test("the self-hosted store matches domains case-sensitively, like AE's LIKE", () => {
  const s = openStore()
  const now = Date.parse("2026-10-06T12:30:00Z")
  const h = Math.floor(now / 1000 / HOUR) * HOUR
  s.replaceAE(h - HOUR, h + HOUR, [{ hour: h, host: "blog.example.com", path: "/", ua: chrome, status: "200", n: 1 }, { hour: h, host: "blog.EXAMPLE.COM", path: "/", ua: chrome, status: "200", n: 2 }])
  assert.deepEqual(build(s.rows(1, "*.example.com", config, now), config).map((x) => [x.host, x.requests]), [["blog.example.com", 1]])
})

test("a domain with only its apex still gets a domain chip, which differs from the apex with aliases", () => {
  const html = render(build({ totals: [{ host: "example.com", status: "200", n: 1 }] }, config), { days: 1, config, generated: "x", today: "2026-10-06" })
  assert.match(html, /<span class="dom"><a href="\?days=1&amp;host=\*\.example\.com">example\.com<\/a><a href="\?days=1&amp;host=example\.com"[^>]*>@<\/a><\/span>/)
})
