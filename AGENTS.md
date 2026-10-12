# AGENTS.md

spor is a stats server for home setups: Cloudflare Workers write one data point per
request to Analytics Engine (AE), and a Basic-auth Worker serves a dashboard and a JSON
API over it. The self-hosted backend (`spor serve`, [selfhost/](selfhost/README.md))
serves the same dashboard and API from SQLite, fed by nginx, `/api/ingest` and an AE
pull. This file is the install guide and the rules for changing the code.

## Install an instance (agent-led)

Ask the owner only for what you cannot discover: their Cloudflare login, which hosts to
count, and a dashboard hostname. Everything else is checkable.

1. **Inventory.** List the owner's hosts and how each is served:
   - `dig +short NS <zone>` shows whether the zone is on Cloudflare.
   - `curl -sI https://<host>/` shows whether it's proxied: `server: cloudflare` and a
     `cf-ray` header. An origin IP from `dig @1.1.1.1` means DNS-only, which a route
     can't see.
   - Repos with a `wrangler.json[c]` are Workers sites. A VPS's `sudo nginx -T` over
     ssh lists the hostnames it serves. It's Tailscale-friendly: `ssh <tailnet-host>`.
2. **Enable Analytics Engine** in the dashboard (Workers → Analytics Engine →
   Enable). Until then, any deploy with an AE binding fails with code 10089. It needs
   no card.
3. **Ignore secrets first.** In the instance repo, write `.gitignore` with `.dev.vars`,
   `node_modules/` and `.wrangler/`, then confirm with `git check-ignore .dev.vars`.
   Do this **before** the file exists. spor's own `.gitignore` is inside the submodule
   and doesn't cover the parent repo.
4. **Create a read-only API token** (Account Analytics:Read) and note the account ID
   from the dashboard URL. Put them, with a generated `DASHBOARD_PASSWORD`, in the
   instance's `.dev.vars`, which git ignores. Never echo them.
5. **Instance repo:** add this repo as a submodule, copy `wrangler.example.jsonc`
   and `tap/wrangler.example.jsonc` (after `mkdir -p tap`), and point their entry points
   into the submodule: `"main": "spor/src/worker.js"` in `wrangler.jsonc` and
   `"main": "../spor/tap/worker.js"` in `tap/wrangler.jsonc`. Then fill in `vars.SPOR.services` (host to a
   short, evidence-based description), `aliases` (other names of a service, such as
   `www.`), `proxyHosts`, the dashboard route and the tap routes.
6. **Write side, per host:**
   - A Workers site gets the tap from `snippets/`, on that site's own repo.
   - A proxied non-Worker host gets a route in `tap/wrangler.jsonc`. A wildcard pair per zone
     (`*.zone/*`, `zone/*`) counts every proxied host, Worker custom domains included. Then
     list the hosts that tap themselves, and the dashboard's own, in `vars.SELF_COUNTED`.
   - A DNS-only host must be orange-clouded first. Ask the owner, and mention
     WebSockets and Cloudflare's 100 s idle timeout.
7. **Deploy:** `npx wrangler login`, `npx wrangler deploy` (it answers 503 until the
   secrets exist), then `node spor/bin/spor.mjs secrets | npx wrangler secret bulk`.
   That command refuses a terminal, so the values are never echoed. Then
   `npx wrangler deploy -c tap/wrangler.jsonc`.
8. **Self-hosted (optional, or instead of the dashboard Worker):** follow
   [selfhost/README.md](selfhost/README.md). Hosts on the machine go under
   `vars.SPOR.local`. Start the service and let the AE backfill finish before you wire up
   nginx.
9. **Verify live:**
   - Before secrets are set, the dashboard returns 503.
   - Without a password, and with a wrong one, it returns 401.
   - With the password it returns 200, with the CSP and `no-store` headers.
   - Send one labelled request per host, using a `User-Agent` with a unique tag,
     and see it come back through AE SQL within a minute or two.
   - Cloudflare's Browser Integrity Check blocks `Python-urllib`, so use curl or a
     browser user agent.

## Rules for changing spor

- **Two backends, one report.** `src/http.js` holds everything both backends serve. A
  backend supplies only the result sets of `queries()`. `src/store.js` mirrors `queries()`:
  the same filters, `LIMIT`s and tie-break. Change one and you change the other. The
  self-hosted backend must give the same `/api/report` as the Worker on the same AE data.
- **Workers Free gives 10 ms of CPU per request and 10,000 AE reads a day.** Aggregate in
  SQL (eleven capped queries, one AE read each, cached 5 minutes) and only classify and
  render in JavaScript. Keep the `LIMIT`s. Warm, a 31-day report costs about 5 ms.
- **Agent classes live in one table.** `CLASSES` in `src/report.js` drives `classOf()` and
  `classSql()`, so a class filter, the bots card and the human counts agree in JavaScript,
  AE and SQLite. Tokens are lowercase-matched substrings without quotes or wildcards. Put a
  narrower class before a broader one (Claude-User carries `claudebot@` in its user agent).
- **The data point has 14 blobs** (see `tap/worker.js`). The IP is written only with
  `RECORD_IP` (tap) or `recordIp` (server); the visitor hash only with a salt (a `SALTS`
  KV namespace, or the server's in-memory daily salt) or with the IP recording on.
- **Every stored value is attacker-written.** Escape everything you render with
  `escapeHtml`, and keep the no-script CSP (`default-src 'none'; style-src
  'unsafe-inline'`): no external CSS, fonts or JavaScript. Inline SVG is fine.
- **Only validated values reach SQL:** `days` is an integer from 1 to 31, `host` is up to
  20 comma-separated names that each match the hostname pattern (a service expands to its
  `aliases` unless the name ends in `!`, and every name to its trailing-dot form; the `!`
  never reaches SQL), and `dataset` must match
  `[A-Za-z0-9_]+`. Filters
  (`parseFilters`) are dropped unless they match: `country` `[A-Z0-9]{2}`, `asn` digits,
  `day` a real date within AE's 92 days, `class` a class id, `path` printable ASCII
  without `'` or `\`, `ip` an IPv4 or IPv6 address. AE SQL has no bound parameters, so
  nothing is escaped, only rejected. SQLite gets bound parameters.
- **Local sources accept only `vars.SPOR.local` hosts.** nginx logs `$server_name`, not
  the Host header, and `/api/ingest` needs its Bearer token.
- **Fail closed.** Missing secrets or an invalid config return 503. Auth comes
  before cache or AE access, and every response is `no-store`. The only way to turn
  auth off is `SPOR_AUTH=off` on the self-hosted server, for one that only a private
  network can reach. The Worker has no such switch.
- **No instance data in this repo:** no real hostnames, descriptions or account IDs.
  Tests use `test/fixture-config.js`.
- `src/report.js` stays import-free, so `node:test` loads it directly. The server uses
  Node built-ins only (`node:sqlite`, `node:http`, `node:dgram`, `node:zlib`). Run
  `npm test` before every commit; it needs no network.
