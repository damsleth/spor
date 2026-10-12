import { test } from "node:test"
import assert from "node:assert/strict"
import { MAP_SCRIPT } from "../src/report.js"

// The map's script run against a stand-in DOM: one map 720 x 288 units shown 720 x 288 pixels,
// starting zoomed to "100 40 360 144", with one circle and its hover label
function harness() {
  const target = () => {
    const on = {}
    return {
      on,
      addEventListener: (type, fn) => { (on[type] ||= []).push(fn) },
      fire(type, init = {}) {
        const e = { defaultPrevented: false, preventDefault() { this.defaultPrevented = true }, stopPropagation() {}, ...init }
        for (const fn of on[type] || []) fn(e)
        return e
      }
    }
  }
  const attrs = (init) => {
    const a = { ...init }
    return { getAttribute: (k) => a[k], setAttribute: (k, v) => { a[k] = String(v) }, a }
  }
  const circle = attrs({ cx: "200", cy: "100", r: "4" })
  const tip = attrs({})
  const group = { querySelector: (sel) => (sel === "circle" ? circle : tip) }
  const svg = Object.assign(target(), attrs({ viewBox: "100 40 360 144" }), {
    querySelectorAll: (sel) => (sel === "circle" ? [circle] : [group]),
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 720, height: 288 })
  })
  const window = target()
  new Function("document", "window", MAP_SCRIPT)({ querySelectorAll: () => [svg] }, window)
  const viewBox = () => svg.getAttribute("viewBox").split(" ").map(Number)
  return { svg, window, circle, tip, viewBox }
}
const down = (h, id = 1, x = 100) => h.svg.fire("pointerdown", { pointerId: id, isPrimary: id === 1, button: 0, clientX: x, clientY: 100 })
const move = (h, id, x) => h.window.fire("pointermove", { pointerId: id, buttons: 1, clientX: x, clientY: 100 })

test("a drag pans by the distance moved, and a second finger can't end it", () => {
  const h = harness()
  down(h)
  move(h, 1, 80)
  assert.equal(h.viewBox()[0], 110, "20 px left at half scale: 10 units right")
  down(h, 2)
  h.svg.fire("lostpointercapture", { pointerId: 2 })
  h.window.fire("pointercancel", { pointerId: 2 })
  move(h, 2, 0)
  assert.equal(h.viewBox()[0], 110, "the second pointer neither ended nor moved the drag")
  move(h, 1, 60)
  assert.equal(h.viewBox()[0], 120)
  h.window.fire("pointercancel", { pointerId: 1 })
  move(h, 1, 0)
  assert.equal(h.viewBox()[0], 120, "its own cancel ends it")
})

test("plain hovering never pans, and only the click that ends a drag is swallowed", () => {
  const h = harness()
  down(h)
  h.window.fire("pointermove", { pointerId: 1, buttons: 0, clientX: 0, clientY: 100 })
  assert.equal(h.viewBox()[0], 100, "a move without the button ends the drag")
  down(h)
  move(h, 1, 50)
  h.window.fire("pointerup", { pointerId: 1 })
  assert.equal(h.svg.fire("click", { detail: 0 }).defaultPrevented, false, "a keyboard click goes through")
  down(h)
  move(h, 1, 50)
  h.window.fire("pointerup", { pointerId: 1 })
  assert.equal(h.svg.fire("click", { detail: 1 }).defaultPrevented, true, "the click ending a drag is swallowed")
  assert.equal(h.svg.fire("click", { detail: 1 }).defaultPrevented, false, "and only that one")
})

test("the wheel zooms around the cursor, keeps circles and labels their size, and stays in the world", () => {
  const h = harness()
  const before = h.viewBox()
  // the cursor at map unit (280, 112): it stays under the cursor
  h.svg.fire("wheel", { deltaY: -100, deltaMode: 0, clientX: 360, clientY: 144 })
  const [x, y, w, hgt] = h.viewBox()
  assert.ok(w < before[2] && Math.abs(w / hgt - 2.5) < 1e-9, "zoomed in, at the map's 2.5:1")
  assert.ok(Math.abs(x + w / 2 - 280) < 1e-9 && Math.abs(y + hgt / 2 - 112) < 1e-9, "around the cursor")
  assert.ok(Math.abs(Number(h.circle.getAttribute("r")) - 4 * (w / 360)) < 1e-9, "the circle keeps its size on screen")
  assert.match(h.tip.getAttribute("transform"), /^translate\(200 100\) scale\(0\.\d+\) translate\(-200 -100\)$/)
  const line = harness()
  line.svg.fire("wheel", { deltaY: 3, deltaMode: 1, clientX: 360, clientY: 144 })
  assert.ok(line.viewBox()[2] / 360 > 1.15, "a line-based wheel notch zooms a useful step")
  for (let i = 0; i < 50; i++) line.svg.fire("wheel", { deltaY: 100, deltaMode: 0, clientX: 700, clientY: 280 })
  assert.deepEqual(line.viewBox(), [0, 0, 720, 288], "zoomed out, the whole world and no further")
})
