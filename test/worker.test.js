import { test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import worker from "../src/worker.js"
import { raw } from "./fixture-config.js"

const env = { DASHBOARD_PASSWORD: "pw", CF_ANALYTICS_TOKEN: "tok", CF_ACCOUNT_ID: "acct", SPOR: raw }
const secrets = ["DASHBOARD_PASSWORD", "CF_ANALYTICS_TOKEN", "CF_ACCOUNT_ID"]
const auth = { authorization: `Basic ${btoa("kim:pw")}` }
const realFetch = globalThis.fetch
let calls

beforeEach(() => {
  calls = []
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init })
    const sql = init.body
    const data = sql.includes("blob7 AS origin") ? [{ host: "proxy.example.net", origin: "https://a.example", n: 1 }]
      : sql.includes("blob5 AS status, SUM") ? [{ host: "proxy.example.net", status: "200", n: 3 }]
      : []
    return new Response(JSON.stringify({ data }), { status: 200 })
  }
})
afterEach(() => {
  globalThis.fetch = realFetch
  delete globalThis.caches
})

function memoryCache() {
  const store = new Map()
  const log = []
  return {
    log,
    store,
    default: {
      async match(req) { log.push(["match", req.url]); const hit = store.get(req.url); return hit ? hit.clone() : undefined },
      async put(req, res) { log.push(["put", req.url, res.headers.get("cache-control")]); store.set(req.url, res.clone()) }
    }
  }
}

const get = (path, headers = auth, e = env, method = "GET") => worker.fetch(new Request(`https://stats.example.com${path}`, { headers, method }), e)

test("fails closed when any secret is missing", async () => {
  for (const missing of secrets) {
    const res = await get("/", auth, { ...env, [missing]: "" })
    assert.equal(res.status, 503, missing)
  }
  assert.equal(calls.length, 0)
})

test("401 with a Basic challenge before touching Analytics Engine", async () => {
  for (const headers of [{}, { authorization: `Basic ${btoa("kim:nope")}` }]) {
    const res = await get("/", headers)
    assert.equal(res.status, 401)
    assert.match(res.headers.get("www-authenticate"), /^Basic realm="spor"/)
    assert.equal(res.headers.get("cache-control"), "no-store")
  }
  assert.equal(calls.length, 0)
})

test("authenticated GET renders HTML with a strict CSP from five AE queries", async () => {
  const res = await get("/?days=7")
  assert.equal(res.status, 200)
  assert.match(res.headers.get("content-type"), /text\/html/)
  assert.match(res.headers.get("content-security-policy"), /default-src 'none'/)
  assert.equal(res.headers.get("cache-control"), "no-store")
  const html = await res.text()
  assert.match(html, /<h2>proxy\.example\.net <span class="desc">CORS proxy with allowlist and secret substitution<\/span><\/h2>/)
  assert.match(html, /https:\/\/a\.example/)
  assert.equal(calls.length, 5)
  for (const c of calls) {
    assert.equal(c.url, "https://api.cloudflare.com/client/v4/accounts/acct/analytics_engine/sql")
    assert.equal(c.init.headers.Authorization, "Bearer tok")
  }
})

test("other paths and methods are refused; AE errors don't leak details", async () => {
  assert.equal((await get("/x")).status, 404)
  assert.equal((await get("/", auth, env, "POST")).status, 405)
  globalThis.fetch = async () => new Response("secret upstream detail", { status: 403 })
  const res = await get("/")
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /secret upstream detail|tok/)
})

// codex review (2026-10-03): the cache layer had no coverage
test("cache: never touched before auth; warm hits skip AE; key isolates accounts; 5 min TTL", async () => {
  const mem = memoryCache()
  globalThis.caches = mem

  assert.equal((await get("/", {})).status, 401)
  assert.equal(mem.log.length, 0, "no cache access for unauthenticated requests")

  assert.equal((await get("/?days=7")).status, 200)
  assert.equal(calls.length, 5)
  assert.equal(mem.log.filter(([op]) => op === "put").length, 5)
  assert.ok(mem.log.filter(([op]) => op === "put").every(([, , cc]) => cc === "max-age=300"))

  assert.equal((await get("/?days=7")).status, 200)
  assert.equal(calls.length, 5, "a warm reload makes no AE calls")

  assert.equal((await get("/?days=7", auth, { ...env, CF_ACCOUNT_ID: "other" })).status, 200)
  assert.equal(calls.length, 10, "another account never reads this account's cached rows")
})

test("GET /api/report returns the JSON model behind the same auth", async () => {
  assert.equal((await get("/api/report", {})).status, 401)
  const res = await get("/api/report?days=3")
  assert.equal(res.status, 200)
  assert.match(res.headers.get("content-type"), /application\/json/)
  assert.equal(res.headers.get("cache-control"), "no-store")
  const body = await res.json()
  assert.equal(body.days, 3)
  const proxy = body.hosts.find((h) => h.host === "proxy.example.net")
  assert.equal(proxy.description, "CORS proxy with allowlist and secret substitution")
  assert.deepEqual(proxy.origins, [["https://a.example", 1]])
})

test("an invalid config fails closed instead of querying", async () => {
  const res = await get("/", auth, { ...env, SPOR: { dataset: "x; DROP" } })
  assert.equal(res.status, 503)
  assert.equal(calls.length, 0)
})

test("a missing vars.SPOR fails closed (503) instead of serving defaults", async () => {
  for (const SPOR of [undefined, null, ""]) {
    const res = await get("/", auth, { ...env, SPOR })
    assert.equal(res.status, 503, String(SPOR))
  }
  assert.equal(calls.length, 0)
})
