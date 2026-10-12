import { test, afterEach } from "node:test"
import assert from "node:assert/strict"
import tap, { dataPoint, visitorId } from "../tap/worker.js"

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch })

test("tap passes the origin response through untouched and writes one redacted point", async () => {
  const upstream = new Response("ok", { status: 207, headers: { "x-origin": "home-server" } })
  let forwarded
  globalThis.fetch = async (req) => { forwarded = req; return upstream }
  const points = []
  const request = new Request("https://app.example.net/floor/3?key=secret", {
    method: "POST",
    headers: { "user-agent": "Mozilla/5.0", referer: "https://example.com/a?token=x", origin: "https://example.com" }
  })
  const response = await tap.fetch(request, { SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) } })
  assert.equal(response, upstream, "same Response object: body, status and headers untouched")
  assert.equal(forwarded, request, "the original request goes to the origin")
  assert.deepEqual(points, [{
    indexes: ["app.example.net"],
    blobs: ["/floor/3", "https://example.com", "Mozilla/5.0", "", "207", "", "https://example.com", "POST", "", "", "", "", "", "", "", ""],
    doubles: [1]
  }])
  assert.doesNotMatch(JSON.stringify(points), /secret|token/)
})

test("tap never breaks the site: missing binding or failing write", async () => {
  globalThis.fetch = async () => new Response("ok")
  const request = new Request("https://app.example.org/")
  assert.equal((await tap.fetch(request, {})).status, 200)
  const failing = { SPOR_ANALYTICS: { writeDataPoint: () => { throw new Error("quota") } } }
  assert.equal((await tap.fetch(request, failing)).status, 200)
})

test("a SELF_COUNTED host passes through without a point", async () => {
  globalThis.fetch = async () => new Response("site")
  const points = []
  const env = { SELF_COUNTED: ["site.example.org"], SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) } }
  assert.equal(await (await tap.fetch(new Request("https://site.example.org/"), env)).text(), "site")
  await tap.fetch(new Request("https://other.example.org/"), env)
  assert.deepEqual(points.map((p) => p.indexes[0]), ["other.example.org"])
})

test("long paths are cut to 64 characters", () => {
  const p = dataPoint(new Request(`https://app.example.org/${"a".repeat(200)}`), 200)
  assert.equal(p.blobs[0].length, 64)
})

const cfRequest = (headers = {}) => {
  const r = new Request("https://app.example.net/", { headers: { "user-agent": "Mozilla/5.0", "cf-connecting-ip": "203.0.113.7", ...headers } })
  Object.defineProperty(r, "cf", { value: { country: "NO", city: "Oslo", region: "Oslo County", asn: 2119, asOrganization: "Telenor Norge AS", latitude: "59.91333", longitude: "10.73897" } })
  return r
}

test("by default the point has geo and network but no IP and no visitor hash", async () => {
  globalThis.fetch = async () => new Response("ok")
  const points = []
  await tap.fetch(cfRequest(), { SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) } })
  assert.deepEqual(points[0].blobs.slice(8), ["Oslo", "Oslo County", "2119", "Telenor Norge AS", "", "", "59.91", "10.74"])
  assert.doesNotMatch(JSON.stringify(points), /203\.0\.113\.7/)
})

test("RECORD_IP stores the client IP and an unsalted daily visitor hash", async () => {
  globalThis.fetch = async () => new Response("ok")
  const points = []
  const env = { RECORD_IP: true, SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) } }
  await tap.fetch(cfRequest(), env)
  await tap.fetch(cfRequest(), env)
  await tap.fetch(cfRequest({ "user-agent": "Other/1.0" }), env)
  const [a, b, c] = points.map((p) => p.blobs)
  assert.equal(a[13], "203.0.113.7")
  assert.match(a[12], /^[0-9a-f]{16}$/)
  assert.equal(a[12], b[12], "same IP and user agent on one day: one visitor")
  assert.notEqual(a[12], c[12])
  assert.equal(await visitorId(cfRequest(), { RECORD_IP: "true" }, "203.0.113.7"), "", "only the boolean true turns it on")
})

test("with a SALTS namespace the hash uses one random salt per day, kept for two days", async () => {
  const kv = new Map()
  const puts = []
  const SALTS = { get: async (k) => kv.get(k) ?? null, put: async (k, v, o) => { puts.push([k, o]); kv.set(k, v) } }
  const day1 = Date.parse("2030-01-01T10:00:00Z")
  const a = await visitorId(cfRequest(), { SALTS }, "203.0.113.7", day1)
  const b = await visitorId(cfRequest(), { SALTS }, "203.0.113.7", day1 + 3600000)
  const c = await visitorId(cfRequest(), { SALTS }, "203.0.113.7", day1 + 86400000)
  assert.equal(a, b)
  assert.notEqual(a, c, "a new day, a new salt")
  assert.deepEqual(puts, [["salt:2030-01-01", { expirationTtl: 172800 }], ["salt:2030-01-02", { expirationTtl: 172800 }]])
  assert.equal(await visitorId(cfRequest(), {}, "203.0.113.7"), "", "no salt and no RECORD_IP: no hash")
})

test("the write waits for ctx.waitUntil, and a failing salt store never breaks the response", async () => {
  globalThis.fetch = async () => new Response("ok", { status: 201 })
  const waits = []
  const points = []
  const env = { SALTS: { get: async () => { throw new Error("kv down") } }, SPOR_ANALYTICS: { writeDataPoint: (p) => points.push(p) } }
  const response = await tap.fetch(cfRequest(), env, { waitUntil: (p) => waits.push(p) })
  assert.equal(response.status, 201)
  assert.equal(waits.length, 1)
  await Promise.all(waits)
  assert.equal(points.length, 0, "the point is dropped, the site answers")
})

test("concurrent first requests of a day share one salt lookup and write one salt", async () => {
  const kv = new Map()
  let puts = 0
  const SALTS = { get: async (k) => { await new Promise((r) => setTimeout(r, 5)); return kv.get(k) ?? null }, put: async (k, v) => { puts++; kv.set(k, v) } }
  const now = Date.parse("2032-02-02T08:00:00Z")
  const ids = await Promise.all(Array.from({ length: 4 }, () => visitorId(cfRequest(), { SALTS }, "203.0.113.7", now)))
  assert.equal(new Set(ids).size, 1)
  assert.equal(puts, 1)
})
