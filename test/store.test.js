import { test } from "node:test"
import assert from "node:assert/strict"
import { openStore, HOUR } from "../src/store.js"
import { build, toJSON, OK_LIMIT } from "../src/report.js"
import { config } from "./fixture-config.js"

const chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
const NOW = Date.parse("2026-10-06T12:30:00Z")
const T = NOW / 1000
const page = (over = {}) => ({ host: "app.example.net", path: "/", referer: "", ua: chrome, country: "NO", status: "200", bot: "", origin: "", method: "GET", ...over })
const plain = (rows) => rows.map((r) => ({ ...r }))

test("a host AE never saw is local from the current hour; one AE knows waits for the next", () => {
  const s = openStore()
  assert.equal(s.addLocal(page(), "nginx", T), true)
  assert.equal(s.cutover("app.example.net"), Math.floor(T / HOUR) * HOUR)

  s.replaceAE(T - 86400, T + 86400, [{ hour: Math.floor(T / HOUR) * HOUR - HOUR, ...page({ host: "app.example.org" }), n: 3 }])
  assert.equal(s.addLocal(page({ host: "app.example.org" }), "nginx", T), false, "AE still owns this hour")
  const next = Math.floor(T / HOUR) * HOUR + HOUR
  assert.equal(s.cutover("app.example.org"), next)
  assert.equal(s.addLocal(page({ host: "app.example.org" }), "nginx", next + 5), true)
})

test("identical points in one hour share a row; n counts them", () => {
  const s = openStore()
  for (let i = 0; i < 3; i++) s.addLocal(page(), "nginx", T + i)
  s.addLocal(page({ path: "/x" }), "nginx", T)
  assert.deepEqual(plain(s.db.prepare("SELECT path, n FROM hits ORDER BY path").all()), [{ path: "/", n: 3 }, { path: "/x", n: 1 }])
})

test("replaceAE replaces only AE rows in its window and never the hours a local source owns", () => {
  const s = openStore()
  const h = Math.floor(T / HOUR) * HOUR
  s.addLocal(page(), "nginx", T)
  s.replaceAE(h - 86400, h + 86400, [
    { hour: h - 2 * HOUR, ...page(), n: 5 },
    { hour: h, ...page(), n: 7 },
    { hour: h, ...page({ host: "blog.example.com" }), n: 2 },
    { hour: h + 2 * 86400, ...page({ host: "blog.example.com" }), n: 99 }
  ])
  const rows = () => plain(s.db.prepare("SELECT hour, host, source, n FROM hits ORDER BY hour, host, source").all())
  assert.deepEqual(rows(), [
    { hour: h - 2 * HOUR, host: "app.example.net", source: "ae", n: 5 },
    { hour: h, host: "app.example.net", source: "nginx", n: 1 },
    { hour: h, host: "blog.example.com", source: "ae", n: 2 }
  ])
  // a re-pull replaces, never adds
  s.replaceAE(h - 86400, h + 86400, [{ hour: h, ...page({ host: "blog.example.com" }), n: 4 }])
  assert.deepEqual(rows(), [
    { hour: h, host: "app.example.net", source: "nginx", n: 1 },
    { hour: h, host: "blog.example.com", source: "ae", n: 4 }
  ])
})

test("rows() answers the five AE result sets with the same filters, and build() counts them", () => {
  const s = openStore()
  const h = Math.floor(T / HOUR) * HOUR
  const day = 86400
  s.replaceAE(h - 40 * day, h + day, [
    { hour: h, ...page({ host: "blog.example.com", path: "/post" }), n: 4 },
    { hour: h, ...page({ host: "blog.example.com", ua: "" }), n: 2 },
    { hour: h, ...page({ host: "blog.example.com", ua: "curl/8" }), n: 1 },
    { hour: h - day, ...page({ host: "blog.example.com", path: "/wp-login.php", status: "404" }), n: 6 },
    { hour: h, ...page({ host: "proxy.example.net", path: "/api.example.com", origin: "https://caller.example" }), n: 3 },
    { hour: h - 10 * day, ...page({ host: "blog.example.com" }), n: 100 }
  ])
  const r = s.rows(7, null, config, NOW)
  assert.deepEqual(Object.keys(r), ["totals", "daily", "ok", "paths", "origins"])
  assert.ok(r.daily.every((x) => /^\d{4}-\d{2}-\d{2}$/.test(x.day)))
  assert.ok(r.ok.every((x) => x.ua !== ""), "empty user agents never reach the detail rows, as in AE")
  assert.deepEqual(plain(r.origins), [{ host: "proxy.example.net", origin: "https://caller.example", n: 3 }])

  const report = toJSON(build(r, config), config, { days: 7 })
  const blog = report.hosts.find((x) => x.host === "blog.example.com")
  assert.equal(blog.requests, 13, "the point 10 days back is outside the 7-day window")
  assert.equal(blog.ok2xx, 7)
  assert.equal(blog.pageviews, 4)
  assert.equal(blog.bots, 3)
  assert.deepEqual(blog.probes, [["/wp-login.php", 6]])
  assert.deepEqual(report.hosts.find((x) => x.host === "proxy.example.net").targets, [["/api.example.com", 3]])

  const one = s.rows(7, "proxy.example.net", config, NOW)
  assert.deepEqual([...new Set(one.totals.map((x) => x.host))], ["proxy.example.net"])
  assert.equal(s.rows(7, "x' OR '1'='1", config, NOW).totals.length, 3, "an unknown host means all hosts")
})

test("the detail rows keep AE's cap, so partial still means partial", () => {
  const s = openStore()
  const h = Math.floor(T / HOUR) * HOUR
  s.replaceAE(h, h + HOUR, Array.from({ length: OK_LIMIT + 5 }, (_, i) => ({ hour: h, ...page({ host: "blog.example.com", path: `/p${i}` }), n: 1 })))
  const r = s.rows(1, null, config, NOW)
  assert.equal(r.ok.length, OK_LIMIT)
  assert.equal(build(r, config).partial, true)
})
