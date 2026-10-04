# Roadmap

v0.1 is what runs today: Cloudflare backend, dashboard, JSON API, tap Worker, site snippets.

Each item names the condition that justifies building it.

- **Self-hosted backend for tailnet-only machines.** A single process with SQLite,
  an ingest endpoint, and nginx access-log ingestion, served with
  `tailscale serve`. It would use the same `report.js`, the same dashboard and the
  same API. *When:* the first host that should be counted but can't sit behind the
  Cloudflare proxy, or a second instance that isn't on Cloudflare.
- **Long-term rollups.** AE keeps 3 months, so history past that needs a daily
  rollup kept somewhere. *When:* an instance has run for about 2 months and wants
  history beyond that.
- **npm package instead of a submodule.** *When:* there's a second instance that
  isn't the author's.
- **Cloudflare Access in front of the dashboard.** *When:* the Zero Trust free
  plan works without a card on file, which reportedly it doesn't today.
