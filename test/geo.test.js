import { test } from "node:test"
import assert from "node:assert/strict"
import { gzipSync } from "node:zlib"
import { mkdtempSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createHash } from "node:crypto"
import { ipToHex, csvFields, updateGeo, openGeo, ASN_URL, cityUrl } from "../src/geo.js"
import { enrich, fromNginx } from "../src/server.js"
import { dataPoint, visitorId } from "../tap/worker.js"

test("ipToHex puts IPv4 and IPv6 on one 32-digit scale", () => {
  assert.equal(ipToHex("1.2.3.4"), "00000000000000000000ffff01020304")
  assert.equal(ipToHex("::ffff:1.2.3.4"), ipToHex("1.2.3.4"))
  assert.equal(ipToHex("2001:db8::1"), "20010db8000000000000000000000001")
  assert.equal(ipToHex("2001:DB8:0:0:0:0:0:1"), ipToHex("2001:db8::1"))
  assert.equal(ipToHex("::"), "0".repeat(32))
  assert.ok(ipToHex("9.255.255.255") < ipToHex("10.0.0.0"))
  for (const bad of ["", "1.2.3", "256.1.1.1", "1:2:3:4:5:6:7:8:9", "1::2::3", "x", "1.2.3.4' OR 1", "::g"]) assert.equal(ipToHex(bad), null, bad)
})

test("csvFields reads DB-IP's quoted fields", () => {
  assert.deepEqual(csvFields('1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.4,153.0'), ["1.0.0.0", "1.0.0.255", "OC", "AU", "Queensland", "South Brisbane", "-27.4", "153.0"])
  assert.deepEqual(csvFields('a,"b, ""c""",d'), ["a", 'b, "c"', "d"])
})

const ASN_TSV = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n2001:db8::\t2001:db8::ffff\t64500\tNO\tEXAMPLE-NET\n"
const CITY_CSV = '0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0\n1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.4,153.0\n2001:db8::,2001:db8::ffff,EU,NO,Oslo,Oslo,59.9,10.7\n'

test("updateGeo loads both sources, falls back a month on 404, and lookups find the range", async () => {
  const dir = mkdtempSync(join(tmpdir(), "spor-geo-"))
  const file = join(dir, "geo.db")
  const now = Date.parse("2030-03-02T00:00:00Z")
  const seen = []
  const fetchImpl = async (url) => {
    seen.push(url)
    if (url === ASN_URL) return new Response(gzipSync(ASN_TSV))
    if (url === cityUrl("2030-02")) return new Response(gzipSync(CITY_CSV))
    return new Response("", { status: 404 })
  }
  const counts = await updateGeo(file, { fetchImpl, now, min: { asn: 1, city: 1 } })
  assert.deepEqual(counts, { asn: 2, city: 2, month: "2030-02" })
  assert.deepEqual(seen, [ASN_URL, cityUrl("2030-03"), cityUrl("2030-02")])
  assert.equal(existsSync(`${file}.tmp`), false)
  const geo = openGeo(file)
  const none = { asn: "", asorg: "", country: "", region: "", city: "", lat: "", lon: "" }
  assert.deepEqual(geo.lookup("1.0.0.7"), { asn: "13335", asorg: "CLOUDFLARENET", country: "AU", region: "Queensland", city: "South Brisbane", lat: "-27.40", lon: "153.00" })
  assert.deepEqual(geo.lookup("2001:db8::42"), { asn: "64500", asorg: "EXAMPLE-NET", country: "NO", region: "Oslo", city: "Oslo", lat: "59.90", lon: "10.70" })
  assert.deepEqual(geo.lookup("1.0.2.1"), none, "unrouted and unknown")
  assert.deepEqual(geo.lookup("not an ip"), none)
  geo.close()
  assert.equal(openGeo(join(dir, "missing.db")), null)
})

test("a failed download leaves the old geo file in place", async () => {
  const dir = mkdtempSync(join(tmpdir(), "spor-geo-"))
  const file = join(dir, "geo.db")
  await assert.rejects(updateGeo(file, { fetchImpl: async () => new Response("", { status: 500 }) }), /answered 500/)
  assert.equal(existsSync(file), false)
  assert.equal(existsSync(`${file}.tmp`), false)
})

test("enrich adds the network and missing geo, hashes the visitor, and keeps the IP only with recordIp", () => {
  const geo = { lookup: () => ({ asn: "64500", asorg: "EXAMPLE-NET", country: "NO", region: "Oslo", city: "Oslo" }) }
  const point = { host: "app.example.net", path: "/", referer: "", ua: "Mozilla/5.0", country: "", status: "200", bot: "", origin: "", method: "GET", city: "Bergen", region: "", ip: "2001:db8::42" }
  const now = Date.parse("2030-01-01T10:00:00Z")
  const a = enrich(point, { geo, now })
  assert.equal(a.ip, "")
  assert.deepEqual([a.asn, a.asorg, a.country, a.region, a.city], ["64500", "EXAMPLE-NET", "NO", "Oslo", "Bergen"], "Cloudflare's city wins over the lookup")
  assert.match(a.visitor, /^[0-9a-f]{16}$/)
  assert.equal(enrich(point, { geo, now: now + 3600000 }).visitor, a.visitor, "same salt all day")
  const b = enrich(point, { geo, recordIp: true, now })
  assert.equal(b.ip, "2001:db8::42")
  assert.equal(b.visitor, createHash("sha256").update("|2030-01-01|app.example.net|2001:db8::42|Mozilla/5.0").digest("hex").slice(0, 16), "unsalted with recordIp, like the tap")
  assert.equal(enrich({ ...point, ip: "" }, { geo: null, now }).visitor, "", "no IP, no visitor")
})

const populated = async (dir) => {
  const file = join(dir, "geo.db")
  await updateGeo(file, { fetchImpl: async (url) => new Response(gzipSync(url === ASN_URL ? ASN_TSV : CITY_CSV)), min: { asn: 1, city: 1 } })
  return file
}

test("an empty but valid download never replaces a working geo file", async () => {
  const file = await populated(mkdtempSync(join(tmpdir(), "spor-geo-")))
  await assert.rejects(updateGeo(file, { fetchImpl: async () => new Response(gzipSync("")) }), /keeping the old geo file/)
  const geo = openGeo(file)
  assert.equal(geo.lookup("1.0.0.7").asn, "13335", "the old file still answers")
  geo.close()
})

test("a download that breaks off mid-stream rejects and leaves the old file", async () => {
  const file = await populated(mkdtempSync(join(tmpdir(), "spor-geo-")))
  const broken = () => new Response(new ReadableStream({
    start(c) { c.enqueue(gzipSync(ASN_TSV).subarray(0, 20)) },
    pull(c) { c.error(new Error("connection reset")) }
  }))
  await assert.rejects(updateGeo(file, { fetchImpl: async () => broken(), min: { asn: 1, city: 1 } }), /connection reset|unexpected end/)
  assert.equal(existsSync(`${file}.tmp`), false)
  const geo = openGeo(file)
  assert.equal(geo.lookup("1.0.0.7").asn, "13335")
  geo.close()
})

test("a wild nginx timestamp or control characters can't break dates or the classes", () => {
  const e = fromNginx(`{"msec":"1e20","host":"app.example.net","uri":"/","ua":"Mozilla\\u0000GPTBot\\u0007"}`)
  assert.ok(Math.abs(e.seconds - Date.now() / 1000) < 60, "out of range: now")
  assert.equal(e.point.ua, "MozillaGPTBot")
  assert.doesNotThrow(() => enrich({ ...e.point, ip: "203.0.113.7" }, { now: e.seconds * 1000 }))
})

test("the daily salt survives out-of-order lines around midnight", () => {
  const point = { host: "app.example.net", ua: "Mozilla/5.0", ip: "203.0.113.7" }
  const d12 = Date.parse("2031-05-12T00:00:05Z")
  const first = enrich(point, { now: d12 }).visitor
  enrich(point, { now: Date.parse("2031-05-11T23:59:58Z") })
  assert.equal(enrich(point, { now: d12 + 1000 }).visitor, first)
})

test("the tap and the server hash a long user agent and an IPv6 address the same way", async () => {
  const ua = `Mozilla/5.0 ${"x".repeat(300)}`
  const now = Date.parse("2031-05-12T10:00:00Z")
  const request = new Request("https://app.example.net/", { headers: { "user-agent": ua } })
  const tap = await visitorId(request, { RECORD_IP: true }, "2001:DB8::1", now)
  const server = enrich({ host: "app.example.net", ua, ip: "2001:DB8::1" }, { recordIp: true, now }).visitor
  assert.equal(tap, server)
  assert.equal(dataPoint(request, 200).blobs[2].length, 256)
})

test("a geo file from before coordinates still answers, without them", async () => {
  const { DatabaseSync } = await import("node:sqlite")
  const file = join(mkdtempSync(join(tmpdir(), "spor-geo-")), "old.db")
  const db = new DatabaseSync(file)
  db.exec(`CREATE TABLE asn (start TEXT PRIMARY KEY, end TEXT, asn TEXT, asorg TEXT, country TEXT);
CREATE TABLE city (start TEXT PRIMARY KEY, end TEXT, country TEXT, region TEXT, city TEXT);
INSERT INTO city VALUES ('${ipToHex("1.0.0.0")}', '${ipToHex("1.0.0.255")}', 'AU', 'Queensland', 'Brisbane');`)
  db.close()
  const geo = openGeo(file)
  assert.deepEqual([geo.lookup("1.0.0.7").city, geo.lookup("1.0.0.7").lat], ["Brisbane", ""])
  geo.close()
})

test("a dotted host name hashes as the same visitor in the tap", async () => {
  const now = Date.parse("2031-05-12T10:00:00Z")
  const a = await visitorId(new Request("https://app.example.net/", { headers: { "user-agent": "x" } }), { RECORD_IP: true }, "203.0.113.7", now)
  const b = await visitorId(new Request("https://app.example.net./", { headers: { "user-agent": "x" } }), { RECORD_IP: true }, "203.0.113.7", now)
  assert.equal(a, b)
})
