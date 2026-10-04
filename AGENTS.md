# AGENTS.md

spor is a stats server for home setups: Cloudflare Workers write one data point per
request to Analytics Engine (AE), and a Basic-auth Worker serves a dashboard and a JSON
API over it. This file is the install guide and the rules for changing the code.

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
   and `tap/wrangler.example.jsonc`, and fill in `vars.SPOR.services` (host to a
   short, evidence-based description), `proxyHosts`, the dashboard route and the
   tap routes.
6. **Write side, per host:**
   - A Workers site gets the tap from `snippets/`, on that site's own repo.
   - A proxied non-Worker host gets a route in `tap/wrangler.jsonc`.
   - A DNS-only host must be orange-clouded first. Ask the owner, and mention
     WebSockets and Cloudflare's 100 s idle timeout.
7. **Deploy:** `npx wrangler login`, `npx wrangler deploy`, then
   `npx wrangler secret bulk` with the secrets as JSON on stdin, built from
   `.dev.vars`. Then `npx wrangler deploy -c tap/wrangler.jsonc`.
8. **Verify live:**
   - Before secrets are set, the dashboard returns 503.
   - Without a password, and with a wrong one, it returns 401.
   - With the password it returns 200, with the CSP and `no-store` headers.
   - Send one labelled request per host, using a `User-Agent` with a unique tag,
     and see it come back through AE SQL within a minute or two.
   - Cloudflare's Browser Integrity Check blocks `Python-urllib`, so use curl or a
     browser user agent.

## Rules for changing spor

- **Workers Free gives 10 ms of CPU per request.** Aggregate in SQL (five capped
  queries) and only classify and render in JavaScript. Keep the `LIMIT`s.
- **Every stored value is attacker-written.** Escape everything you render with
  `escapeHtml`, and keep the no-script CSP (`default-src 'none'; style-src
  'unsafe-inline'`): no external CSS, fonts or JavaScript. Inline SVG is fine.
- **Only validated values reach SQL:** `days` is an integer from 1 to 31, `host`
  must be a configured host, and `dataset` must match `[A-Za-z0-9_]+`.
- **Fail closed.** Missing secrets or an invalid config return 503. Auth comes
  before cache or AE access, and every response is `no-store`.
- **No instance data in this repo:** no real hostnames, descriptions or account IDs.
  Tests use `test/fixture-config.js`.
- `src/report.js` stays import-free, so `node:test` loads it directly. Run
  `npm test` before every commit; it needs no network.
