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
  assert.match(html, /<a href="\?days=7&amp;host=blog\.example\.com&amp;day=2026-10-06&amp;country=NO"><rect/)
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
