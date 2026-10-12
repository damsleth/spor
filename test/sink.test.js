import { test, afterEach } from "node:test"
import assert from "node:assert/strict"
import tap from "../tap/worker.js"
import { makeToken, readToken, findToken, bait } from "../tap/sink.js"
import { baitKind, sinkable, parseFilters, queries, build, render, toJSON } from "../src/report.js"
import { openStore, HOUR } from "../src/store.js"
import { config } from "./fixture-config.js"

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch })
const chrome = "Mozilla/5.0 (Macintosh) Chrome/140.0 Safari/537.36"

test("bait kinds cover the most probed paths and nothing else", () => {
  const want = {
    "/.env": "env", "/.env.local": "env", "/.env.production": "env", "/src/.env": "env", "/@fs/app/.env": "env", "/.env.save": "env", "/userfiles/backup.env": "env",
    "/.git/config": "git", "/.git-credentials": "git", "/.git/HEAD": "git",
    "/.aws/credentials": "aws", "/.boto": "aws", "/.s3cfg": "aws", "/.npmrc": "npm",
    "/Dockerfile": "docker", "/docker-compose.yml": "docker", "/info.php": "php", "/wp-content/plugins/x/wp_filemanager.php": "php",
    "/userfiles": "userfiles", "/userfiles/": "userfiles",
    "/": "", "/about": "", "/.environment": "", "/env": "", "/api/fs/read": "", "/style.css": "", "/.gitignore": "", "/php": ""
  }
  for (const [path, kind] of Object.entries(want)) assert.equal(baitKind(path), kind, path)
})

test("AI assistants and search crawlers are spared, unless they ignore robots.txt", () => {
  const ua = (s) => ({ ua: s, bot: "" })
  assert.equal(sinkable(ua("Mozilla/5.0 (compatible; Claude-User/1.0; +claudebot@anthropic.com)")), false)
  assert.equal(sinkable(ua("Mozilla/5.0 (compatible; Googlebot/2.1)")), false)
  assert.equal(sinkable(ua("Mozilla/5.0 (compatible; PerplexityBot/1.0)")), false)
  assert.equal(sinkable(ua("Mozilla/5.0 (compatible; Perplexity-User/1.0)")), true)
  assert.equal(sinkable(ua("Mozilla/5.0 compatible; ChatGPT-User/1.0")), true)
  assert.equal(sinkable(ua("Mozilla/5.0 zgrab/0.x")), true)
  assert.equal(sinkable(ua("")), true)
  assert.equal(sinkable(ua(chrome)), true)
})

test("a canary token carries its probe, opaquely, only for the secret that made it", async () => {
  const t = await makeToken("s3cret", { host: "example.com", ip: "203.0.113.7", kind: "env", now: Date.parse("2030-01-02T03:04:30Z") })
  assert.match(t, /^spk_live_[A-Za-z0-9_-]+$/)
  assert.doesNotMatch(t, /example|203/)
  assert.deepEqual(await readToken("s3cret", t), { at: "2030-01-02 03:04", host: "example.com", ip: "203.0.113.7", kind: "env" })
  assert.equal(await readToken("other", t), null)
  const random = await makeToken("", { host: "example.com", ip: "", kind: "env" })
  assert.match(random, /^spk_live_[0-9a-f]{48}$/)
  assert.equal(await readToken("s3cret", random), null)
})

test("findToken looks where a stolen key goes: URL, Bearer, Basic and X-Api-Key", () => {
  const t = "spk_live_abcdefghijklmnopqrstuvwxyz012345"
  const req = (url, headers = {}) => new Request(url, { headers })
  assert.equal(findToken(req(`https://e.com/x?key=${t}`)), t)
  assert.equal(findToken(req("https://e.com/x", { authorization: `Bearer ${t}` })), t)
  assert.equal(findToken(req("https://e.com/x", { authorization: `Basic ${btoa(`deploy:${t}`)}` })), t)
  assert.equal(findToken(req("https://e.com/x", { "x-api-key": t })), t)
  assert.equal(findToken(req("https://e.com/x", { authorization: "Basic !!!" })), "")
  assert.equal(findToken(req("https://e.com/%E0%A4%A")), "")
})

test("every bait carries the token and points back at the probed host", () => {
  for (const kind of ["env", "git", "aws", "npm", "docker", "php"]) {
    const b = bait(kind, "example.com", "spk_live_TOKEN0123456789abcdef")
    assert.match(b.body, /spk_live_TOKEN0123456789abcdef/, kind)
    assert.match(b.body, /example\.com\/_internal\//, kind)
  }
  assert.match(bait("userfiles", "example.com", "x").body, /backup\.env/)
  assert.equal(bait("nope", "example.com", "x"), null)
})

const sinkEnv = (extra = {}) => {
  const points = []
  return { points, env: { SINKHOLE: true, RECORD_IP: true, CANARY_SECRET: "s3cret", SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) }, ...extra } }
}
const probe = (path, headers = {}) => new Request(`https://example.com${path}`, { headers: { "user-agent": "zgrab/0.x", "cf-connecting-ip": "198.51.100.9", ...headers } })

test("the tap baits a probe only when the origin has nothing there", async () => {
  const { points, env } = sinkEnv()
  globalThis.fetch = async () => new Response("not found", { status: 404 })
  const res = await tap.fetch(probe("/.env"), env)
  assert.equal(res.status, 200)
  const body = await res.text()
  const token = /spk_live_[A-Za-z0-9_-]+/.exec(body)[0]
  assert.deepEqual(await readToken("s3cret", token).then((c) => [c.host, c.ip, c.kind]), ["example.com", "198.51.100.9", "env"])
  assert.equal(points[0].blobs[16], "bait:env")
  assert.equal(points[0].blobs[4], "200")

  globalThis.fetch = async () => new Response("<!doctype html>app", { status: 200, headers: { "content-type": "text/html" } })
  assert.match(await (await tap.fetch(probe("/.git/config"), env)).text(), /\[remote "origin"\]/, "an SPA's HTML fallback is no git config")
  assert.match(await (await tap.fetch(probe("/login.php"), env)).text(), /^<!doctype html>app/, "a real PHP page stays")
  assert.match(await (await tap.fetch(probe("/userfiles"), env)).text(), /^<!doctype html>app/, "a real /userfiles page stays")
  globalThis.fetch = async () => new Response("nf", { status: 404 })
  assert.match(await (await tap.fetch(probe("/info.php"), env)).text(), /phpinfo/, "a missing PHP page gets bait")

  globalThis.fetch = async () => new Response("REAL=1", { status: 200, headers: { "content-type": "text/plain" } })
  assert.equal(await (await tap.fetch(probe("/.env"), env)).text(), "REAL=1", "a real file is never hidden")

  globalThis.fetch = async () => new Response("nope", { status: 404 })
  assert.equal((await tap.fetch(probe("/.env", { "user-agent": "Mozilla/5.0 (compatible; Claude-User/1.0)" }), env)).status, 404, "an assistant gets the origin's answer")
  assert.equal((await tap.fetch(probe("/.env"), { ...env, SINKHOLE: "true" })).status, 404, "only the boolean true turns it on")
  assert.equal((await tap.fetch(probe("/.env"), { ...env, SELF_COUNTED: ["example.com"] })).status, 404, "a host that counts itself gets no bait: it already counted the 404")
})

test("a used canary key is recorded with its probe, answered 403, and announced once", async () => {
  const sent = []
  const { points, env } = sinkEnv({ CANARY_WEBHOOK: "https://ntfy.example/canary", CANARY_WEBHOOK_TOKEN: "tk" })
  const token = await makeToken("s3cret", { host: "bait.example.com", ip: "198.51.100.9", kind: "git", now: Date.parse("2030-01-02T03:04:00Z") })
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://ntfy.example")) sent.push(init)
    return new Response("origin")
  }
  const use = () => tap.fetch(probe("/_internal/git/app-infra.git/info/refs", { authorization: `Basic ${btoa(`deploy:${token}`)}`, "cf-connecting-ip": "192.0.2.50" }), env)
  const res = await use()
  assert.equal(res.status, 403)
  await use()
  assert.equal(points[0].blobs[16], "use:git")
  assert.equal(points[0].blobs[17], "bait.example.com|198.51.100.9|2030-01-02 03:04|git")
  assert.equal(sent.length, 1, "one alert per key per hour")
  assert.equal(sent[0].headers.authorization, "Bearer tk")
  assert.match(sent[0].body, /git bait on bait\.example\.com, given to 198\.51\.100\.9.*used by 192\.0\.2\.50/)
})

test("/_internal/ without a key is a Basic challenge, and the sinkhole never breaks the origin", async () => {
  const { points, env } = sinkEnv()
  globalThis.fetch = async () => new Response("origin")
  const res = await tap.fetch(probe("/_internal/git/x.git/info/refs"), env)
  assert.equal(res.status, 401)
  assert.match(res.headers.get("www-authenticate"), /^Basic/)
  assert.equal(points[0].blobs[16], "challenge")
  assert.equal(await (await tap.fetch(probe("/_internal/x"), { ...env, SINKHOLE: false })).text(), "origin")
  globalThis.fetch = async () => new Response("nf", { status: 404 })
  const broken = { ...env, CANARY_SECRET: { toString() { throw new Error("no key") } } }
  assert.equal((await tap.fetch(probe("/.env"), broken)).status, 404, "a failing token falls back to the origin")
})

test("the sinkhole view filters every query, lists canary uses, and escapes what attackers wrote", () => {
  const f = parseFilters(new URLSearchParams("view=sink"))
  assert.deepEqual(f, { view: "sink" })
  assert.deepEqual(parseFilters(new URLSearchParams("view=other")), {})
  const q = queries(7, null, config, Date.now(), f)
  assert.match(q.totals, /blob17 != ''/)
  assert.match(q.sinkuse, /blob17 LIKE 'use:%'/)
  assert.equal(queries(7, null, config).sinkuse, undefined, "the traffic view runs no sinkhole queries")
  const evil = `<img src=x onerror=alert(1)>`
  const model = build({
    totals: [{ host: "blog.example.com", status: "200", n: 3 }],
    sinkkinds: [{ kind: "bait:env", host: "blog.example.com", n: 2 }, { kind: "use:env", host: "blog.example.com", n: 1 }],
    sinkuse: [{ at: "2030-01-02 03:00:00", host: "blog.example.com", path: `/x${evil}`, kind: "use:env", ctx: `${evil}|198.51.100.9|2030-01-02 03:04|env`, ip: "192.0.2.50", asorg: evil, country: "NL", n: 1 }]
  }, config)
  const html = render(model, { days: 7, host: null, filters: f, config, generated: "x" })
  assert.doesNotMatch(html, /<img/)
  assert.match(html, /canary alerts/)
  assert.match(html, /href="\?days=7&amp;view=sink&amp;ip=192\.0\.2\.50"/)
  assert.match(html, /env bait served/)
  assert.deepEqual(toJSON(model, config, { filters: f }).sink.bait, [["bait:env", 2], ["use:env", 1]])
})

test("the store keeps a local host's sinkhole rows after its cutover", () => {
  const s = openStore()
  const h = Math.floor(Date.parse("2026-10-06T12:00:00Z") / 1000 / HOUR) * HOUR
  s.addLocal({ host: "app.example.net", path: "/" }, "nginx", h + 10)
  s.replaceAE(h - HOUR, h + HOUR, [
    { hour: h, host: "app.example.net", path: "/", status: "200", n: 5 },
    { hour: h, host: "app.example.net", path: "/_internal/x", status: "403", sink: "use:env", sinkctx: "a|b|c|env", n: 1 }
  ])
  assert.deepEqual(s.db.prepare("SELECT source, sink, n FROM hits ORDER BY source").all().map((r) => ({ ...r })), [{ source: "ae", sink: "use:env", n: 1 }, { source: "nginx", sink: "", n: 1 }])
})

test("without RECORD_IP no IP reaches a token, a record or an alert", async () => {
  const sent = []
  const { points, env } = sinkEnv({ RECORD_IP: false, CANARY_WEBHOOK: "https://ntfy.example/c" })
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://ntfy.example")) sent.push(init)
    return new Response("nf", { status: 404 })
  }
  const body = await (await tap.fetch(probe("/.env"), env)).text()
  const token = /spk_live_[A-Za-z0-9_-]+/.exec(body)[0]
  assert.equal((await readToken("s3cret", token)).ip, "")
  const old = await makeToken("s3cret", { host: "example.com", ip: "198.51.100.9", kind: "env" })
  await tap.fetch(probe("/_internal/x", { authorization: `Bearer ${old}`, "cf-connecting-ip": "192.0.2.50" }), env)
  assert.doesNotMatch(JSON.stringify(points), /198\.51\.100\.9|192\.0\.2\.50/)
  assert.doesNotMatch(sent[0].body, /198\.51|192\.0\.2/)
})

test("a failed alert is retried on the next use instead of going quiet for an hour", async () => {
  const sent = []
  let up = false
  const { env } = sinkEnv({ CANARY_WEBHOOK: "https://ntfy.example/c" })
  globalThis.fetch = async (url) => {
    if (String(url).startsWith("https://ntfy.example")) {
      sent.push(up)
      if (!up) return new Response("down", { status: 503 })
    }
    return new Response("ok")
  }
  const token = await makeToken("s3cret", { host: "example.com", ip: "198.51.100.9", kind: "env" })
  const use = () => tap.fetch(probe("/_internal/x", { authorization: `Bearer ${token}` }), env)
  await use()
  up = true
  await use()
  await use()
  assert.deepEqual(sent, [false, true], "down, then delivered, then quiet")
})

test("tokens for the longest host names and IPv6 addresses survive the trip", async () => {
  const host = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(57)}.example`.slice(0, 253)
  const ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
  const token = await makeToken("s3cret", { host, ip, kind: "docker" })
  const found = findToken(new Request(`https://e.com/x?k=${token}`))
  assert.equal(found, token)
  assert.equal((await readToken("s3cret", found)).host, host)
  assert.equal(findToken(new Request(`https://e.com/x?k=${token}${"x".repeat(700)}`)), "", "an overlong run is not a token")
})

test("an unreadable key shows as unknown bait, not a made-up probe", () => {
  const model = build({ sinkuse: [{ at: "2030-01-02 03:00:00", host: "blog.example.com", path: "/_internal/x", kind: "use:unknown", ctx: "", ip: "192.0.2.50", asorg: "", country: "", n: 1 }, { at: "2030-01-02 03:00:00", host: "blog.example.com", path: "/_internal/y", kind: "use:env", ctx: "unknown", ip: "192.0.2.51", asorg: "", country: "", n: 1 }] }, config)
  assert.deepEqual(model.canaries.map((c) => c.from), [null, null])
  const html = render(model, { days: 7, host: null, filters: { view: "sink" }, config, generated: "x" })
  assert.doesNotMatch(html, /undefined/)
  assert.equal((html.match(/unknown bait/g) || []).length, 2)
})

test("a local host's probe counts once as traffic, and its bait still shows in the sinkhole view", () => {
  const s = openStore()
  const now = Date.parse("2026-10-06T12:30:00Z")
  const h = Math.floor(now / 1000 / HOUR) * HOUR
  s.addLocal({ host: "app.example.net", path: "/.env", status: "404" }, "nginx", h + 10)
  s.replaceAE(h - HOUR, h + HOUR, [
    { hour: h, host: "app.example.net", path: "/.env", status: "200", sink: "bait:env", n: 1 },
    { hour: h, host: "app.example.net", path: "/_internal/x", status: "401", sink: "challenge", n: 1 }
  ])
  const traffic = toJSON(build(s.rows(1, "app.example.net", config, now), config), config).hosts[0]
  assert.equal(traffic.requests, 2, "nginx's 404 and the challenge; the bait row is not traffic")
  const sink = toJSON(build(s.rows(1, "app.example.net", config, now, { view: "sink" }), config), config, { filters: { view: "sink" } })
  assert.deepEqual(sink.sink.bait, [["bait:env", 1], ["challenge", 1]])
  s.replaceAE(h - HOUR, h + HOUR, [])
  assert.equal(s.db.prepare("SELECT COUNT(*) AS c FROM hits WHERE source != 'nginx'").get().c, 0, "a re-pull replaces the bait rows too")
})

test("a header of repeated prefixes is scanned in linear time and holds no token", () => {
  const evil = "spk_live_".repeat(7281) + "x".repeat(601)
  const t = performance.now()
  for (let i = 0; i < 20; i++) assert.equal(findToken(new Request("https://e.com/", { headers: { "x-api-key": evil } })), "")
  assert.ok((performance.now() - t) / 20 < 5, "well under a millisecond each")
  const good = "spk_live_" + "a".repeat(40)
  assert.equal(findToken(new Request("https://e.com/", { headers: { "x-api-key": `${"spk_live_x ".repeat(3)}${good}` } })), good, "a later run can still be the token")
})

test("a stalled webhook locks a key's alerts for a minute, not forever", async () => {
  const sent = []
  const { env } = sinkEnv({ CANARY_WEBHOOK: "https://ntfy.example/c" })
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://ntfy.example")) {
      sent.push(Date.now())
      return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)))
    }
    return new Response("ok")
  }
  const token = await makeToken("s3cret", { host: "example.com", ip: "198.51.100.9", kind: "git" })
  const waits = []
  const use = () => tap.fetch(probe("/_internal/x", { authorization: `Bearer ${token}` }), env, { waitUntil: (p) => waits.push(p) })
  const until = async (ok) => { for (let i = 0; i < 200 && !ok(); i++) await new Promise((r) => setTimeout(r, 5)) }
  await use()
  await until(() => sent.length === 1)
  await use()
  await new Promise((r) => setTimeout(r, 50))
  assert.equal(sent.length, 1, "one alert in flight at a time")
  // the stalled call times out after 5 seconds and releases the key
  await Promise.all(waits)
  await use()
  await until(() => sent.length === 2)
  assert.equal(sent.length, 2, "after the call timed out, the next use alerts again")
  await Promise.all(waits)
})
