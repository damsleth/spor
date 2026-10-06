import { test } from "node:test"
import assert from "node:assert/strict"
import { createSocket } from "node:dgram"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { startServer, fromNginx, fromDataPoint, syncAE, aeWindowQuery, AE_RETENTION_DAYS } from "../src/server.js"
import { openStore } from "../src/store.js"
import { dataPoint } from "../tap/worker.js"
import { config, raw } from "./fixture-config.js"

const chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
const basic = (pass) => `Basic ${Buffer.from(`kim:${pass}`).toString("base64")}`
const tempDb = () => join(mkdtempSync(join(tmpdir(), "spor-")), "spor.db")
const env = (over = {}) => ({ DASHBOARD_PASSWORD: "pw", SPOR_DB: tempDb(), SPOR_LISTEN: "127.0.0.1:0", ...over })

async function withServer(over, fn, spor = raw) {
  const app = await startServer({ spor, env: env(over), fetchImpl: async () => new Response(JSON.stringify({ data: [] })) })
  try {
    await fn(app, (path, init = {}) => fetch(`http://127.0.0.1:${app.port}${path}`, init))
  } finally {
    await app.stop()
  }
}

test("nginx syslog lines become store points: path without query, referer and origin as origins, '-' as empty", () => {
  const line = `<190>Oct  6 10:35:35 spor: {"msec":"1791283000.123","host":"app.example.net","uri":"/a/b?token=secret","status":"200","referer":"https://news.example/item?id=1","ua":"${chrome}","country":"-","origin":"-","method":"GET"}`
  const e = fromNginx(line)
  assert.equal(e.seconds, 1791283000.123)
  assert.deepEqual(e.point, { host: "app.example.net", path: "/a/b", referer: "https://news.example", ua: chrome, country: "", status: "200", bot: "", origin: "", method: "GET" })
  for (const bad of ["<190>no json here", "<190>spor: {broken", "<190>spor: null"]) assert.equal(fromNginx(bad), null, bad)
  assert.equal(fromNginx(`{"host":"a","uri":"/${"x".repeat(200)}"}`).point.path.length, 64)
})

test("the tap's own data point is a valid ingest body", () => {
  const request = new Request("https://app.example.net/page?q=1", { headers: { referer: "https://r.example/x", "user-agent": chrome } })
  assert.deepEqual(fromDataPoint(dataPoint(request, 200)), { host: "app.example.net", path: "/page", referer: "https://r.example", ua: chrome, country: "", status: "200", bot: "", origin: "", method: "GET" })
  for (const bad of [null, {}, { indexes: "x", blobs: [] }]) assert.equal(fromDataPoint(bad), null)
})

test("the server fails closed: no password or a broken config answers 503, auth before anything else", async () => {
  await withServer({ DASHBOARD_PASSWORD: "" }, async (_, get) => {
    assert.equal((await get("/")).status, 503)
    assert.equal((await get("/api/ingest", { method: "POST", body: "{}" })).status, 503)
  })
  await withServer({}, async (_, get) => {
    assert.equal((await get("/", { headers: { authorization: basic("pw") } })).status, 503)
  }, { dataset: "x; DROP" })
  await withServer({}, async (_, get) => {
    const res = await get("/")
    assert.equal(res.status, 401)
    assert.match(res.headers.get("www-authenticate"), /^Basic realm="spor"/)
    assert.equal(res.headers.get("cache-control"), "no-store")
    assert.equal((await get("/", { method: "POST", headers: { authorization: basic("pw") } })).status, 405)
    assert.equal((await get("/x", { headers: { authorization: basic("pw") } })).status, 404)
  })
})

test("dashboard and /api/report come from SQLite, with the Worker's headers", async () => {
  await withServer({}, async (app, get) => {
    app.store.addLocal({ host: "app.example.net", path: "/", referer: "", ua: chrome, country: "NO", status: "200", bot: "", origin: "", method: "GET" }, "nginx")
    const res = await get("/?days=7", { headers: { authorization: basic("pw") } })
    assert.equal(res.status, 200)
    assert.match(res.headers.get("content-security-policy"), /default-src 'none'/)
    assert.equal(res.headers.get("cache-control"), "no-store")
    const html = await res.text()
    assert.match(html, /<h2>app\.example\.net <span class="desc">demo app/)
    assert.doesNotMatch(html, /cached up to/)
    const api = await (await get("/api/report?days=1", { headers: { authorization: basic("pw") } })).json()
    assert.equal(api.hosts[0].host, "app.example.net")
    assert.equal(api.hosts[0].pageviews, 1)
    const head = await get("/", { method: "HEAD", headers: { authorization: basic("pw") } })
    assert.equal(head.status, 200)
    assert.equal(await head.text(), "")
  })
})

test("ingest: off without INGEST_TOKEN, Bearer auth, local hosts only, capped body", async () => {
  const point = (host) => ({ indexes: [host], blobs: ["/", "", chrome, "NO", "200", "", "", "GET"], doubles: [1] })
  const post = (get, body, token = "tok") => get("/api/ingest", { method: "POST", headers: { authorization: `Bearer ${token}` }, body: typeof body === "string" ? body : JSON.stringify(body) })
  await withServer({}, async (_, get) => assert.equal((await post(get, point("app.example.net"))).status, 404))
  await withServer({ INGEST_TOKEN: "tok" }, async (app, get) => {
    assert.equal((await post(get, point("app.example.net"), "nope")).status, 401)
    assert.equal((await get("/api/ingest", { headers: { authorization: "Bearer tok" } })).status, 405)
    assert.equal((await post(get, point("blog.example.com"))).status, 400, "configured but not local")
    assert.equal((await post(get, "{nope")).status, 400)
    assert.equal((await post(get, Array.from({ length: 101 }, () => point("app.example.net")))).status, 413)
    assert.equal((await post(get, "x".repeat(70000))).status, 413)
    assert.equal((await post(get, [point("app.example.net"), point("app.example.org")])).status, 204)
    assert.equal(app.store.db.prepare("SELECT SUM(n) AS n FROM hits WHERE source = 'ingest'").get().n, 2)
  })
})

test("nginx datagrams on SPOR_SYSLOG are counted for local hosts only", async () => {
  await withServer({ SPOR_SYSLOG: "127.0.0.1:0" }, async (app) => {
    const send = (msg) => new Promise((resolve) => {
      const sock = createSocket("udp4")
      sock.send(msg, app.udp.address().port, "127.0.0.1", () => { sock.close(); resolve() })
    })
    const msec = (Date.now() / 1000).toFixed(3)
    await send(`<190>spor: {"msec":"${msec}","host":"app.example.org","uri":"/","status":"200","referer":"","ua":"${chrome}","country":"NO","origin":"","method":"GET"}`)
    await send(`<190>spor: {"msec":"${msec}","host":"blog.example.com","uri":"/","status":"200","referer":"","ua":"${chrome}","country":"NO","origin":"","method":"GET"}`)
    for (let i = 0; i < 50 && !app.store.db.prepare("SELECT COUNT(*) AS c FROM hits").get().c; i++) await new Promise((r) => setTimeout(r, 10))
    assert.deepEqual(app.store.db.prepare("SELECT host, source, n FROM hits").all().map((r) => ({ ...r })), [{ host: "app.example.org", source: "nginx", n: 1 }])
  })
})

test("AE sync: backfills the retention a day at a time, then re-pulls two days; hours are parsed as UTC", async () => {
  const store = openStore()
  const now = Date.parse("2026-10-06T12:00:00Z") / 1000
  const queries = []
  const fetchImpl = async (url, init) => {
    queries.push(init.body)
    assert.equal(init.headers.Authorization, "Bearer tok")
    // AE answers n as a string and hour as "YYYY-MM-DD HH:MM:SS" in UTC
    const data = init.body.includes("timestamp >= toDateTime('2026-10-06 00:00:00')")
      ? [{ hour: "2026-10-06 09:00:00", host: "blog.example.com", path: "/", referer: "", ua: chrome, country: "NO", status: "200", bot: "", origin: "", method: "GET", n: "4" }]
      : []
    return new Response(JSON.stringify({ data }))
  }
  const secrets = { accountId: "acct", token: "tok" }
  assert.equal(await syncAE(store, secrets, config, { now, fetchImpl }), 1)
  assert.equal(queries.length, AE_RETENTION_DAYS + 1)
  assert.deepEqual(store.db.prepare("SELECT hour, n FROM hits").all().map((r) => ({ ...r })), [{ hour: Date.parse("2026-10-06T09:00:00Z") / 1000, n: 4 }])
  queries.length = 0
  await syncAE(store, secrets, config, { now, fetchImpl })
  assert.equal(queries.length, 2, "yesterday and today")
  assert.equal(store.db.prepare("SELECT SUM(n) AS n FROM hits").get().n, 4, "a re-pull replaces, never doubles")
})

test("the AE window query only interpolates computed times and a validated dataset", () => {
  const q = aeWindowQuery("spor_analytics", 0, 3600)
  assert.match(q, /timestamp >= toDateTime\('1970-01-01 00:00:00'\) AND timestamp < toDateTime\('1970-01-01 01:00:00'\)/)
  assert.match(q, /SUM\(_sample_interval\) AS n/)
  assert.throws(() => aeWindowQuery("x; DROP", 0, 1))
})
