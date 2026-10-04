import { test } from "node:test"
import assert from "node:assert/strict"
import { loadConfig, toJSON, clampDays, validHost, queries, build, render, escapeHtml, checkAuth, safeEqual, DEFAULT_DAYS, MAX_DAYS, OK_LIMIT } from "../src/report.js"
import { config, raw } from "./fixture-config.js"

const chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
const basic = (user, pass) => `Basic ${Buffer.from(`${user}:${pass}`, "utf8").toString("base64")}`

test("days is an int in [1, 31]; anything else falls back to the default", () => {
  assert.equal(clampDays("7"), 7)
  assert.equal(clampDays("0"), 1)
  assert.equal(clampDays("999"), MAX_DAYS)
  for (const bad of [null, undefined, "", "abc", "7; DROP", "-1", "1e3", "7 ", " 7"]) assert.equal(clampDays(bad), DEFAULT_DAYS, String(bad))
})

test("host must be one of the known hosts", () => {
  assert.equal(validHost("blog.example.com", config), "blog.example.com")
  for (const bad of ["x' OR 1=1 --", "evil.example", "", null, "BLOG.EXAMPLE.COM"]) assert.equal(validHost(bad, config), null, String(bad))
})

test("SQL only ever interpolates a clamped int and an allowlisted host", () => {
  const q = queries("7", "blog.example.com", config)
  for (const sql of Object.values(q)) {
    assert.match(sql, /INTERVAL '7' DAY/)
    assert.match(sql, /index1 = 'blog\.example\.com'/)
    assert.match(sql, /FROM spor_analytics WHERE/)
    assert.match(sql, /SUM\(_sample_interval\) AS n/)
    assert.match(sql, /FORMAT JSON$/)
  }
  const hostile = queries("7' OR 1=1 --", "x' OR '1'='1", config)
  for (const sql of Object.values(hostile)) {
    assert.doesNotMatch(sql, /OR 1=1|OR '1'/)
    assert.match(sql, new RegExp(`INTERVAL '${DEFAULT_DAYS}' DAY`))
    assert.doesNotMatch(sql, /index1 =/)
  }
  assert.match(queries(7, null, config).ok, /LIMIT \d+/)
})

const fixture = {
  totals: [
    { host: "blog.example.com", status: "200", n: 61 },   // consistent with the detail rows below
    { host: "blog.example.com", status: "404", n: 40 },
    { host: "proxy.example.net", status: "200", n: 9 },
    { host: "proxy.example.net", status: "403", n: 3 }
  ],
  daily: [
    { day: "2026-10-02 00:00:00", host: "blog.example.com", n: 30 },
    { day: "2026-10-03 00:00:00", host: "blog.example.com", n: "22" }
  ],
  ok: [
    { host: "blog.example.com", path: "/#/post/a", referer: "https://news.ycombinator.com", ua: chrome, country: "NO", bot: "", method: "VIEW", n: 5 },
    { host: "blog.example.com", path: "/#/post/a", referer: "https://blog.example.com", ua: chrome, country: "SE", bot: "", method: "VIEW", n: 2 },
    { host: "blog.example.com", path: "/#/post/a", referer: "", ua: "Mozilla/5.0 (compatible; Googlebot/2.1)", country: "US", bot: "", method: "VIEW", n: 3 },
    { host: "blog.example.com", path: "/app.js", referer: "", ua: chrome, country: "NO", bot: "", method: "GET", n: 50 },
    { host: "blog.example.com", path: "/<script>alert(1)</script>", referer: "", ua: chrome, country: "NO", bot: "", method: "GET", n: 1 },
    { host: "proxy.example.net", path: "/", referer: "", ua: "", country: "KR", bot: "", method: "GET", n: 8 },
    { host: "proxy.example.net", path: "/", referer: "", ua: "Hello from Palo Alto Networks", country: "US", bot: "", method: "GET", n: 1 }
  ],
  paths: [
    { host: "blog.example.com", path: "/wp-login.php", status: "404", n: 30 },
    { host: "proxy.example.net", path: "/x.example.org", status: "200", n: 4 },
    { host: "proxy.example.net", path: "/wp.php", status: "200", n: 6 },
    { host: "proxy.example.net", path: "/.well-known", status: "200", n: 2 }
  ],
  origins: [{ host: "proxy.example.net", origin: "https://app.example", n: 4 }]
}

test("classification: bots, assets and self-referrals are not human traffic", () => {
  const [blog, proxy] = build(fixture, config)
  assert.equal(blog.host, "blog.example.com")
  assert.equal(blog.requests, 101)
  assert.equal(blog.pageviews, 5 + 2 + 1)
  assert.equal(blog.bots, 3)
  assert.deepEqual([...blog.referers], [["https://news.ycombinator.com", 5]])
  assert.deepEqual([...blog.countries].sort(), [["NO", 6], ["SE", 2]])
  assert.deepEqual([...blog.probes], [["/wp-login.php", 30]])
  assert.deepEqual([...blog.daily], [["2026-10-02", 30], ["2026-10-03", 22]])
  assert.equal(proxy.pageviews, 0, "empty and named-scanner UAs are bots")
  assert.equal(proxy.bots, 9)
  assert.deepEqual([...proxy.targets], [["/x.example.org", 4]], "scanner paths are not proxy targets")
  assert.deepEqual([...proxy.origins], [["https://app.example", 4]])
})

test("render escapes every attacker-written value", () => {
  const html = render(build(fixture, config), { days: 7, host: null, config, generated: "<now>" })
  assert.doesNotMatch(html, /<script>alert/)
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
  assert.match(html, /&lt;now&gt;/)
  assert.match(html, /<h2>blog\.example\.com <span class="desc">personal tech blog<\/span><\/h2>/)
  assert.match(html, /title="CORS proxy with allowlist and secret substitution">proxy\.example\.net<\/a>/)
  assert.equal(escapeHtml(`"'<>&`), "&quot;&#39;&lt;&gt;&amp;")
  assert.match(render([], { days: 1, host: null, config, generated: "x" }), /No data in this window/)
})

test("basic auth: right password only, user name ignored, malformed headers refused", () => {
  assert.ok(checkAuth(basic("kim", "s3cret:with:colons"), "s3cret:with:colons"))
  assert.ok(checkAuth(basic("", "pw"), "pw"))
  assert.ok(!checkAuth(basic("kim", "wrong"), "pw"))
  assert.ok(!checkAuth(basic("kim", "pw"), ""), "no configured password never authenticates")
  for (const bad of [null, undefined, "", "Basic", "Basic !!!", "Bearer abc", `Basic ${btoa("nocolon")}`]) {
    assert.ok(!checkAuth(bad, "pw"), String(bad))
  }
  assert.ok(safeEqual("abc", "abc") && !safeEqual("abc", "abd") && !safeEqual("abc", "abcd") && !safeEqual("", "a"))
})

// ---- review findings (2026-10-03), each red before its fix ---------------------------------

test("bot share is bots over all 2xx requests, taken from the uncapped totals", () => {
  const model = build({
    totals: [{ host: "blog.example.com", status: "200", n: 101 }],
    ok: [
      { host: "blog.example.com", path: "/app.js", ua: chrome, method: "GET", n: 90 },
      { host: "blog.example.com", path: "/#/post/a", ua: chrome, method: "VIEW", n: 1 }
    ]
  }, config)
  const [blog] = model
  assert.equal(blog.pageviews, 1)
  assert.equal(blog.bots, 10, "bots = 2xx total - human 2xx (empty-UA rows never reach the detail query)")
  assert.match(render(model, { days: 7, host: null, config, generated: "x" }), /10% of 2xx from bots/)
})

test("empty user agents are excluded from the capped detail query, and a full cap is flagged", () => {
  assert.match(queries(7, null, config).ok, /blob3 != ''/)
  assert.match(queries(7, null, config).ok, new RegExp(`LIMIT ${OK_LIMIT} `))
  const full = Array.from({ length: OK_LIMIT }, (_, i) => ({ host: "blog.example.com", path: `/p${i}`, ua: chrome, method: "GET", n: 1 }))
  const model = build({ totals: [{ host: "blog.example.com", status: "200", n: OK_LIMIT }], ok: full }, config)
  assert.equal(model.partial, true)
  assert.match(render(model, { days: 7, host: null, config, generated: "x" }), /partial/i)
  assert.equal(build(fixture, config).partial, false)
})

test("non-ASCII passwords authenticate (Basic credentials are UTF-8)", () => {
  assert.ok(checkAuth(basic("kim", "blåbær"), "blåbær"))
  assert.ok(!checkAuth(basic("kim", "blabar"), "blåbær"))
})

test("the daily series has one bar per day in the window, zero-filled", () => {
  const model = build({
    totals: [{ host: "blog.example.com", status: "200", n: 5 }],
    daily: [
      { day: "2026-10-01 00:00:00", host: "blog.example.com", n: 3 },
      { day: "2026-10-03 00:00:00", host: "blog.example.com", n: 2 }
    ]
  }, config)
  const html = render(model, { days: 3, host: null, config, generated: "x", today: "2026-10-03" })
  const card = html.slice(html.indexOf('<section'))
  const bars = [...card.matchAll(/<rect [^>]*><title>([^<]+)<\/title>/g)].map((m) => m[1])
  assert.deepEqual(bars, ["2026-10-01: 3", "2026-10-02: 0", "2026-10-03: 2"])
})

test("every configured host has a short description, and the descriptions are escaped", () => {
  assert.deepEqual(config.hosts, Object.keys(raw.services))
  for (const [host, desc] of Object.entries(config.services)) {
    assert.ok(desc && desc.length <= 60, host)
  }
  const html = render(build({ totals: [{ host: "app.example.net", status: "200", n: 1 }] }, config), { days: 1, host: null, config, generated: "x" })
  assert.match(html, /demo app, &quot;quoted&quot; \(home server\)/)
  const unknown = render(build({ totals: [{ host: "new.example", status: "200", n: 1 }] }, config), { days: 1, host: null, config, generated: "x" })
  assert.match(unknown, /<h2>new\.example<\/h2>/)
})

test("config: defaults, lowercased hosts, and a dataset name that can't inject SQL", () => {
  const empty = loadConfig(undefined)
  assert.equal(empty.dataset, "spor_analytics")
  assert.equal(empty.title, "spor")
  assert.deepEqual(empty.hosts, [])
  assert.equal(validHost("blog.example.com", empty), null, "no configured hosts, no host filter")
  assert.deepEqual(loadConfig({ services: { "Blog.Example.COM": "x" } }).hosts, ["blog.example.com"])
  assert.equal(loadConfig(JSON.stringify(raw)).services["proxy.example.net"], raw.services["proxy.example.net"])
  for (const bad of ["x; DROP TABLE y", "a-b", "spor analytics", "t'"]) assert.throws(() => loadConfig({ dataset: bad }), /dataset/, bad)
  assert.match(queries(7, null, loadConfig({ dataset: "custom_ds" })).totals, /FROM custom_ds WHERE/)
})

test("the API model is plain JSON with descriptions and sorted breakdowns", () => {
  const json = toJSON(build(fixture, config), config, { days: 7, host: null })
  assert.equal(json.days, 7)
  assert.equal(json.partial, false)
  const blog = json.hosts.find((h) => h.host === "blog.example.com")
  assert.equal(blog.description, "personal tech blog")
  assert.equal(blog.pageviews, 8)
  assert.deepEqual(blog.referers, [["https://news.ycombinator.com", 5]])
  assert.deepEqual(blog.daily, [["2026-10-02", 30], ["2026-10-03", 22]])
  assert.deepEqual(JSON.parse(JSON.stringify(json)), json, "survives a JSON round trip")
})

test("the title comes from config and is escaped", () => {
  const html = render([], { days: 1, host: null, config: loadConfig({ title: "<home> stats" }), generated: "x" })
  assert.match(html, /<title>&lt;home&gt; stats<\/title>/)
  assert.doesNotMatch(html, /<home>/)
})

test("hostile host, description and referer cannot inject markup into the SVG or tables", () => {
  const evil = `"><script>alert(1)</script><svg onload=alert(2)>`
  const cfg = loadConfig({ services: { [evil]: evil }, title: evil })
  const model = build({
    totals: [{ host: evil, status: evil, n: 5 }, { host: evil, status: "200", n: 5 }],
    daily: [{ day: "2026-10-03 00:00:00", host: evil, n: 5 }],
    ok: [{ host: evil, path: evil, referer: evil, ua: chrome, country: evil, method: "VIEW", n: 1 }]
  }, cfg)
  const html = render(model, { days: 3, host: evil, config: cfg, generated: evil, today: "2026-10-03" })
  assert.doesNotMatch(html, /<script/)
  assert.doesNotMatch(html, /<svg onload/)
  assert.doesNotMatch(html, /"><script/)
  assert.doesNotMatch(html, /onload=alert\(2\)>/)
  assert.match(html, /&lt;script&gt;alert\(1\)/)
  assert.equal((html.match(/<svg /g) || []).length, (html.match(/<\/svg>/g) || []).length)
})
