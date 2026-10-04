import { test, afterEach } from "node:test"
import assert from "node:assert/strict"
import tap, { dataPoint } from "../tap/worker.js"

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
    blobs: ["/floor/3", "https://example.com", "Mozilla/5.0", "", "207", "", "https://example.com", "POST"],
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

test("long paths are cut to 64 characters", () => {
  const p = dataPoint(new Request(`https://app.example.org/${"a".repeat(200)}`), 200)
  assert.equal(p.blobs[0].length, 64)
})
