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
  referers to their origin. Unique visitors come from a daily hash with a salt
  that expires (a KV namespace), so hashes can't be linked across days. For your
  own use you can store client IPs instead: `RECORD_IP` on the tap, `recordIp`
  for the self-hosted server. Attacker-written values are escaped under a
  no-script CSP, and the dashboard is behind Basic auth.
- **Who, not just how many.** Bots and AI agents are sorted into classes (AI
  assistants fetching for a person, AI search, AI training, search engines,
  scanners, scripts, browsers on cloud networks). City, region and network come
  from Cloudflare, or for self-hosted hosts from IPtoASN and DB-IP Lite, and
  a world map shows visitors by city (inline SVG, Natural Earth's outline).
  Every table row is a link that filters the whole dashboard: by day (then by
  the hour), country, network, class, path or IP. One card covers everything
  in view; service chips pick one service or several, and `aliases` fold a
  service's other names (www.) into it.
- **Everything you host.** The pass-through `tap/` Worker counts anything behind
  the Cloudflare proxy, such as nginx on a VPS, a Pi on your tailnet or Azure.
  With wildcard routes it counts every proxied host in a zone, Worker sites
  included. Workers sites can also write their own data point (see `snippets/`).
- **Agent-led setup.** [AGENTS.md](AGENTS.md) is written so that an agent can
  stand up an instance end to end.
- **Or self-hosted.** `spor serve` runs the same dashboard and API from one Node
  process with SQLite, fed by nginx, an ingest endpoint and an Analytics Engine
  pull. It counts tailnet-only and DNS-only hosts too. See
  [selfhost/](selfhost/README.md).

## CLI

```bash
npm link                                  # puts `spor` on your PATH
spor report --days 7                      # stats per host in the terminal
spor report --json | jq '.hosts[0]'       # the same model as /api/report
spor ask "who reads my blog, and from where?"
spor hosts                                # configured hosts and what they are
spor check                                # config, secrets, connectivity
spor serve                                # the self-hosted backend (selfhost/README.md)
```

The CLI reads either a running instance, using `SPOR_URL` and `SPOR_PASSWORD`,
or Analytics Engine directly, using `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN`
from the environment or `./.dev.vars`. Instance mode works from anywhere: your
laptop, a box on your tailnet, or an ssh session.

`spor ask` pipes the report and your question to any command that reads stdin.
It uses the first of these that is set: `--llm`, then `SPOR_LLM`, then
`vars.SPOR.llm`, otherwise `claude -p`. Other commands that work include
`codex exec -` and `ollama run llama3`. Each breakdown in the report is trimmed
to its top 20 entries, and stored values are passed as data, never as
instructions.

## Parts

| Part | What it does |
|---|---|
| `src/worker.js` | The Cloudflare backend: the dashboard and API over Analytics Engine SQL |
| `src/server.js`, `src/store.js` | The self-hosted backend: the same dashboard and API over SQLite, fed by nginx, `/api/ingest` and an AE pull |
| `src/http.js` | What both backends serve: the dashboard at `/` and the JSON API at `/api/report?days=&host=`, behind Basic auth |
| `src/report.js` | Pure logic: config, SQL, classification (bots, assets, probes, referers) and rendering |
| `bin/spor.mjs` | The CLI: `report`, `ask`, `hosts`, `check`. Node built-ins only |
| `tap/worker.js` | A pass-through route Worker for hosts that aren't Workers |
| `snippets/` | How a Workers site writes its own data point, including hash-routed single-page apps |
| `selfhost/` | systemd unit, nginx log format and dashboard vhost, install guide |

## An instance

Your instance is its own small repo containing `wrangler.jsonc` (routes, plus your
hosts and descriptions in `vars.SPOR`), `tap/wrangler.jsonc` and `.dev.vars`, with
this repo as a git submodule. See [AGENTS.md](AGENTS.md).

```bash
git init my-spor && cd my-spor
printf '.dev.vars\nnode_modules/\n.wrangler/\n' > .gitignore   # BEFORE any secret exists
git check-ignore -q .dev.vars && echo "secrets are ignored"
git submodule add https://github.com/damsleth/spor spor
mkdir -p tap
cp spor/wrangler.example.jsonc wrangler.jsonc        # set main to "spor/src/worker.js"
cp spor/tap/wrangler.example.jsonc tap/wrangler.jsonc # set main to "../spor/tap/worker.js"
cp spor/.dev.vars.example .dev.vars                  # fill in; never commit
npx wrangler login
npx wrangler deploy                                  # answers 503 until the secrets are set
node spor/bin/spor.mjs secrets | npx wrangler secret bulk
npx wrangler deploy -c tap/wrangler.jsonc
```

`.dev.vars` only feeds `wrangler dev`. Production secrets are uploaded separately.
`spor secrets` reads `.dev.vars` the same way the CLI does (quotes stripped, comments
ignored, all three keys required) and prints JSON for `wrangler secret bulk`. It refuses to
print to a terminal, so the values never reach your screen or your shell history.

spor's own `.gitignore` sits inside the submodule and **does not protect your instance**.
The instance needs its own `.gitignore` for `.dev.vars`, created before the file is.

Update it with `git submodule update --remote spor` and redeploy.

## Status

v0.2 runs on Cloudflare, or self-hosted next to it or instead of it, and is in daily use
for one home setup. See the [roadmap](ROADMAP.md). MIT licensed.
