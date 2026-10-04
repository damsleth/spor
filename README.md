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

## CLI

```bash
npm link                                  # puts `spor` on your PATH
spor report --days 7                      # stats per host in the terminal
spor report --json | jq '.hosts[0]'       # the same model as /api/report
spor ask "who reads my blog, and from where?"
spor hosts                                # configured hosts and what they are
spor check                                # config, secrets, connectivity
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
| `src/worker.js` | The dashboard at `/` and the JSON API at `/api/report?days=&host=`, behind Basic auth |
| `src/report.js` | Pure logic: config, SQL, classification (bots, assets, probes, referers) and rendering |
| `bin/spor.mjs` | The CLI: `report`, `ask`, `hosts`, `check`. Node built-ins only |
| `tap/worker.js` | A pass-through route Worker for hosts that aren't Workers |
| `snippets/` | How a Workers site writes its own data point, including hash-routed single-page apps |

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

v0.1 runs on Cloudflare and is in daily use for one home setup. A self-hosted
backend for tailnet-only machines is on the [roadmap](ROADMAP.md). MIT licensed.
