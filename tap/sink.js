// spor's sinkhole, for the tap: bait for paths scanners probe for secrets, and canary tokens in that
// bait that point back at the host they came from. Whoever uses a stolen token on one of your hosts
// is recorded (and announced, with a webhook), along with the probe that got it.
//
// A token is "spk_live_" and the AES-GCM encryption of "v1|<minute>|<host>|<ip>|<kind>" under a key
// derived from the CANARY_SECRET secret, so a used token says which probe it came from, and a
// scanner sees only an opaque key. Without the secret, tokens are random and say nothing.
// The bait points at /_internal/ on the probed host: requests there without a token get a 401
// challenge, so git and HTTP clients send the credentials they found.

// long enough for a 253-character host and an IPv6 address; a longer run is not a token of ours
export const TOKEN = /spk_live_[A-Za-z0-9_-]{20,600}(?![A-Za-z0-9_-])/
export const INTERNAL = "/_internal/"

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0))
const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("")

let keyCache = { secret: null, key: null }
async function keyFor(secret) {
  if (keyCache.secret !== secret) {
    const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`spor-canary|${secret}`))
    keyCache = { secret, key: await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]) }
  }
  return keyCache.key
}

export async function makeToken(secret, { host, ip, kind, now = Date.now() }) {
  if (!secret) return `spk_live_${hex(24)}`
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plain = new TextEncoder().encode(`v1|${Math.floor(now / 60000)}|${host}|${ip}|${kind}`)
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyFor(secret), plain))
  const out = new Uint8Array(iv.length + sealed.length)
  out.set(iv)
  out.set(sealed, iv.length)
  return `spk_live_${b64url(out)}`
}

// token -> { at, host, ip, kind } for a token this secret made, else null
export async function readToken(secret, token) {
  if (!secret || !token) return null
  try {
    const bytes = unb64url(token.slice("spk_live_".length))
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, await keyFor(secret), bytes.slice(12))
    const [v, minute, host, ip, kind] = new TextDecoder().decode(plain).split("|")
    if (v !== "v1") return null
    return { at: new Date(Number(minute) * 60000).toISOString().slice(0, 16).replace("T", " "), host, ip, kind }
  } catch {
    return null
  }
}

// a canary token anywhere a client would put a stolen key: the URL, Authorization (Bearer or Basic,
// which git sends as base64 user:password) or X-Api-Key
export function findToken(request) {
  const found = (s) => TOKEN.exec(s || "")?.[0] || ""
  const auth = request.headers.get("authorization") || ""
  let basic = ""
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(auth.trim())
  if (m) {
    try {
      basic = atob(m[1])
    } catch {
      basic = ""
    }
  }
  let url = request.url
  try {
    url = decodeURIComponent(request.url)
  } catch {
    // a malformed escape: search the raw URL
  }
  return found(url) || found(auth) || found(basic) || found(request.headers.get("x-api-key"))
}

// A believable secrets file of each kind, with the canary token where the secrets go
const slug = (host) => host.split(".")[0].replace(/[^a-z0-9]/g, "") || "app"
export function bait(kind, host, token) {
  const app = slug(host)
  const api = `https://${host}${INTERNAL}api/v2`
  const git = `https://deploy:${token}@${host}${INTERNAL}git/${app}-infra.git`
  const text = (body) => ({ body, type: "text/plain; charset=utf-8" })
  switch (kind) {
    case "env":
      return text(`APP_NAME=${app}
APP_ENV=production
APP_KEY=base64:${btoa(hex(16))}
APP_DEBUG=false
APP_URL=https://${host}

DB_CONNECTION=pgsql
DB_HOST=db-primary.internal
DB_PORT=5432
DB_DATABASE=${app}_production
DB_USERNAME=${app}_app
DB_PASSWORD=${hex(12)}

REDIS_URL=redis://default:${hex(10)}@cache.internal:6379/0

INTERNAL_API_URL=${api}
INTERNAL_API_KEY=${token}
DEPLOY_REPOSITORY=${git}
`)
    case "git":
      return text(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = ${git}
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)
    case "aws":
      return text(`[default]
# the internal artifact store; S3-compatible
endpoint_url = ${api}/s3
aws_access_key_id = SPKA${hex(8).toUpperCase()}
aws_secret_access_key = ${token}
region = eu-north-1
`)
    case "npm":
      return text(`registry=https://${host}${INTERNAL}npm/
//${host}${INTERNAL}npm/:_authToken=${token}
always-auth=true
`)
    case "docker":
      return text(`FROM node:22-alpine
WORKDIR /app
ARG NPM_TOKEN=${token}
RUN echo "//${host}${INTERNAL}npm/:_authToken=\${NPM_TOKEN}" > .npmrc
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV INTERNAL_API_URL=${api} INTERNAL_API_KEY=${token}
CMD ["node", "server.js"]
`)
    case "php":
      return {
        type: "text/html; charset=utf-8",
        body: `<!DOCTYPE html><html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.2.12</h1>
<table><tr><th>Variable</th><th>Value</th></tr>
<tr><td>$_SERVER['SERVER_NAME']</td><td>${host}</td></tr>
<tr><td>$_ENV['APP_ENV']</td><td>production</td></tr>
<tr><td>$_ENV['INTERNAL_API_URL']</td><td>${api}</td></tr>
<tr><td>$_ENV['INTERNAL_API_KEY']</td><td>${token}</td></tr>
<tr><td>$_ENV['DEPLOY_REPOSITORY']</td><td>${git}</td></tr>
</table></body></html>
`
      }
    case "userfiles":
      return {
        type: "text/html; charset=utf-8",
        body: `<!DOCTYPE html><html><head><title>Index of /userfiles</title></head><body><h1>Index of /userfiles</h1>
<pre><a href="/userfiles/backup.env">backup.env</a>        2026-09-30 03:12  1.2K
<a href="/userfiles/.git/config">.git/config</a>       2026-09-30 03:12  312
</pre></body></html>
`
      }
    default:
      return null
  }
}

// What a request to /_internal/ gets: with a token, a refusal that looks like a revoked key; without
// one, a Basic challenge, so git and curl send the credentials they found
export function internalResponse(hasToken) {
  if (hasToken) return new Response(JSON.stringify({ error: "invalid_token", message: "This API key has been revoked." }), { status: 403, headers: { "content-type": "application/json", "cache-control": "no-store" } })
  return new Response("Authentication required\n", { status: 401, headers: { "www-authenticate": "Basic realm=\"internal\"", "content-type": "text/plain", "cache-control": "no-store" } })
}
