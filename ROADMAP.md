# Roadmap

v0.3 is what runs today: Cloudflare backend, dashboard, JSON API, tap Worker, site snippets,
the self-hosted backend (`spor serve`: SQLite, nginx over syslog, `/api/ingest`, AE pull),
bot and AI classes, city and network, daily unique visitors, optional client IPs, and
drill-down filters by day, hour, country, network, class, path and IP.

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
- **Verified AI agents.** A claimed GPTBot or ClaudeBot can be checked against the IP lists
  OpenAI and Anthropic publish, or Cloudflare's signed agents (Web Bot Auth). *When:* spoofed
  AI user agents distort the AI numbers; today a group of uniform "compatible; XBot/1.0"
  user agents (KimiBot, GrokBot, Qwenbot...) looks like one crawler.
- **Smaller geo file.** Ranges as 16-byte blobs instead of 32-character hex would halve the
  ~900 MB. *When:* disk on the self-hosted machine gets tight.
