# Roadmap

v0.2 is what runs today: Cloudflare backend, dashboard, JSON API, tap Worker, site snippets,
and the self-hosted backend (`spor serve`: SQLite, nginx over syslog, `/api/ingest`, AE pull).

Each item names the condition that justifies building it.

- **Long-term rollups.** AE keeps 3 months. The self-hosted store keeps
  everything, so this applies only to Cloudflare-only instances. *When:* such an
  instance has run for about 2 months and wants history beyond that.
- **Views past 31 days on the self-hosted backend.** SQLite has no CPU budget, so
  `MAX_DAYS` could grow there. *When:* the store holds more than a month and
  someone wants to see it.
- **npm package instead of a submodule.** *When:* there's a second instance that
  isn't the author's.
- **Cloudflare Access in front of the dashboard.** *When:* the Zero Trust free
  plan works without a card on file, which reportedly it doesn't today.
