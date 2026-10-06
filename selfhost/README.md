# Self-hosted spor

The same dashboard and JSON API as the Worker, served by one Node process with a SQLite
file, for machines that can't sit behind the Cloudflare proxy: a box that is only on your
tailnet, or DNS-only hosts. It needs Node 22.13 or newer and nothing from npm.

```
nginx ──syslog (udp, loopback)──┐
tailnet machine ──POST /api/ingest──┤──> spor serve ──> SQLite ──> /  and  /api/report
Analytics Engine ──SQL pull every 5 min─┘
```

| Source | What it counts | Turned on by |
|---|---|---|
| nginx | every request to a host in `vars.SPOR.local`, one JSON log line each | `SPOR_SYSLOG` and `nginx-spor-log.conf` |
| `POST /api/ingest` | data points in the tap's Analytics Engine shape, from any machine that can reach the server | `INGEST_TOKEN` |
| Analytics Engine | everything the Workers and the tap write, backfilled for AE's 3 months of retention | `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN` |

With all three you get one dashboard. Workers sites keep writing to AE, and hosts on the
machine are counted by nginx, including DNS-only hosts that AE never sees.

**No double counting.** A host is counted by exactly one source at any time. The first
time a local point (nginx or ingest) arrives for a host in `local`, the host gets a
*cutover*: the start of the next hour, or the current hour if AE has no data for it.
Before the cutover the host's data comes from AE, and from the cutover on it comes from
the local source. AE rows for that host after the cutover are ignored. Counts for a host
can change at its cutover: the tap sees requests that Cloudflare answers itself, and nginx
sees requests that never pass Cloudflare.

**Same numbers.** The store keeps hourly buckets with the AE columns. `src/store.js`
answers the same five queries as `queries()` in `src/report.js`, with the same filters and
`LIMIT`s and a deterministic tie-break. `build()`, `render()` and `toJSON()` then run
unchanged. Fed the same AE data, the two backends return identical reports.

## Configure

In the instance's `wrangler.jsonc`, list the hosts that the machine serves under
`vars.SPOR.local`. Each one must also appear in `services`:

```jsonc
"local": ["app.example.com", "pi.example.com"]
```

Environment, read from the process environment or `./.dev.vars`:

| Variable | Default | |
|---|---|---|
| `DASHBOARD_PASSWORD` | (required) | Basic-auth password, the same as the Worker's |
| `SPOR_DB` | `spor.db` | SQLite file |
| `SPOR_LISTEN` | `127.0.0.1:2650` | HTTP address |
| `SPOR_SYSLOG` | (off) | UDP address for nginx, e.g. `127.0.0.1:2651` |
| `INGEST_TOKEN` | (off) | Bearer token for `POST /api/ingest` |
| `CF_ACCOUNT_ID`, `CF_ANALYTICS_TOKEN` | (off) | AE pull (Account Analytics:Read) |
| `SPOR_AE_SYNC_MINUTES` | `5` | AE pull interval |

## Install (systemd and nginx)

1. Put the instance on the machine as `/opt/spor`, owned by root: `wrangler.jsonc` plus the
   `spor/` submodule. You can clone it, or copy it with
   `tar -c --exclude .dev.vars --exclude node_modules . | ssh host 'sudo tar -C /opt/spor --no-same-owner -x'`.
2. Write the secrets to `/etc/spor/env` (root, mode 600) through a pipe, so they are never
   echoed:
   `grep -E '^(CF_ACCOUNT_ID|CF_ANALYTICS_TOKEN|DASHBOARD_PASSWORD)=' .dev.vars | ssh host 'sudo sh -c "umask 077; mkdir -p /etc/spor; cat > /etc/spor/env"'`.
   Add `INGEST_TOKEN=$(openssl rand -hex 24)` if you want ingest.
3. Copy `spor.service` to `/etc/systemd/system/`, then run
   `systemctl daemon-reload && systemctl enable --now spor`. Wait for
   `spor: AE sync pulled N rows` in `journalctl -u spor`. Let the backfill finish before
   step 4, so the cutovers land after the AE history.
4. Install `nginx-spor-log.conf` in the http context, sorted before any file that uses
   `spor_json`. A server block that has its own `access_log` replaces the inherited one, so
   add the syslog line there too.
5. Install `nginx-spor-site.conf` with your dashboard host. Point its DNS at the machine's
   Tailscale IP, DNS only. Then run `nginx -t && systemctl reload nginx`.

Without nginx, `tailscale serve --bg 2650` publishes the dashboard on the machine's
`ts.net` name instead.

## Verify

- Without a password, and with a wrong one, `/` and `/api/report` return 401. With the
  password they return 200, with the CSP and `no-store` headers.
- From outside the tailnet, nginx answers 403.
- Send a labelled request to a local host, then look for it in `/api/report?days=1`. A host
  AE already counts appears only from its cutover, at the next full hour.
- Parity: `/api/report?days=31` should match the Worker's for every host that AE feeds.

## Ingest from another machine

```bash
curl -X POST https://stats.example.com/api/ingest -H "Authorization: Bearer $INGEST_TOKEN" \
  -d '{"indexes":["pi.example.com"],"blobs":["/","","Mozilla/5.0 ...","NO","200","","","GET"],"doubles":[1]}'
```

The body is one data point or an array of up to 100, at most 64 KB. Every host must be in
`local`. The server answers 204, or 400, 401 or 413. `dataPoint()` in `tap/worker.js`
produces exactly this shape.
