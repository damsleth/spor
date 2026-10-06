// Example instance config used by the tests. Real instances keep theirs in wrangler.jsonc vars.SPOR.
import { loadConfig } from "../src/report.js"

export const raw = {
  title: "spor",
  dataset: "spor_analytics",
  services: {
    "blog.example.com": "personal tech blog",
    "proxy.example.net": "CORS proxy with allowlist and secret substitution",
    "app.example.net": "demo app, \"quoted\" (home server)",
    "app.example.org": "another home-server app"
  },
  proxyHosts: ["proxy.example.net"],
  // counted by the self-hosted backend itself (nginx log, /api/ingest)
  local: ["app.example.net", "app.example.org"]
}
export const config = loadConfig(raw)
