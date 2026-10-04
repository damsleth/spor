# spor

**Stats for everything you host at home, at 0 kr a month.**

*spor* is Norwegian for *trace* or *track*. It counts every request to every site
and service you run, including static sites, Workers, and apps on a home server or
VPS. It keeps the data in Cloudflare's free Analytics Engine and shows it on a
private dashboard, in a JSON API and in a CLI you can ask questions in plain
language.

- **Free, with no card.** It runs on the Workers Free plan and Analytics Engine's
  free tier. No Cloudflare Pro, no Logpush, no Access.
- **Private by default.** It records no IP and no query string, and reduces
  referers to their origin. Attacker-written values are escaped under a
  no-script CSP, and the dashboard is behind Basic auth.
- **Everything you host.** Workers sites write their own data point (see
  `snippets/`). Anything else behind the Cloudflare proxy, such as nginx on a
  VPS, a Pi on your tailnet or Azure, is counted by the pass-through `tap/`
  Worker.
- **Agent-led setup.** [AGENTS.md](AGENTS.md) is written so that an agent can
  stand up an instance end to end.

## Parts

| Part | What it does |
|---|---|
| `src/worker.js` | The dashboard at `/` and the JSON API at `/api/report?days=&host=`, behind Basic auth |
| `src/report.js` | Pure logic: config, SQL, classification (bots, assets, probes, referers) and rendering |
| `tap/worker.js` | A pass-through route Worker for hosts that aren't Workers |
| `snippets/` | How a Workers site writes its own data point, including hash-routed single-page apps |

## An instance

Your instance is its own small repo containing `wrangler.jsonc` (routes, plus your
hosts and descriptions in `vars.SPOR`), `tap/wrangler.jsonc` and `.dev.vars`, with
this repo as a git submodule. See [AGENTS.md](AGENTS.md).

```bash
git submodule add https://github.com/damsleth/spor spor
cp spor/wrangler.example.jsonc wrangler.jsonc        # set main to "spor/src/worker.js"
cp spor/tap/wrangler.example.jsonc tap/wrangler.jsonc # set main to "../../spor/tap/worker.js"
npx wrangler deploy && npx wrangler deploy -c tap/wrangler.jsonc
```

Update it with `git submodule update --remote spor` and redeploy.

## Status

v0.1 runs on Cloudflare and is in daily use for one home setup. A self-hosted
backend for tailnet-only machines is on the [roadmap](ROADMAP.md). MIT licensed.
