# claude-worker-relay

Cloudflare Worker front end for Anthropic-compatible HTTPS requests. Every
upstream request leaves through a signed HTTPS relay on a VPS, so the upstream
sees the VPS address rather than Cloudflare's.

```text
Claude Code → Worker → HTTPS relay (VPS) → dynamic HTTPS upstream:443
```

> **Package independence:** this directory is a standalone deployment artifact.
> It carries its own copy of the relay pipeline, signing and target code, so it
> installs, tests, builds and deploys without `codex-worker/` or the repository
> root present. The Codex Worker carries its own copy; the two are kept
> byte-compatible by `protocol/conformance.py`, which drives both TypeScript
> implementations over the same vectors as the Rust relay.

The relay is the **only** egress path. There is no direct-`fetch()` mode and no
proxy mode: an incomplete relay configuration fails the request instead of
falling back, because a fallback would send traffic from Cloudflare's address
space and defeat the reason the relay exists.

## How this differs from the Codex Worker

One deliberate difference, and it is the whole reason the two exist separately:

| | `codex-worker/` | `claude-worker/` (this package) |
| --- | --- | --- |
| Caller identity | **Synthesized.** Callers are not Codex, so a coherent Codex identity is projected into headers and `client_metadata`. | **Forwarded untouched.** The caller really is Claude Code and already sends correct identity. |
| Body | May receive injected `client_metadata` | Never modified |
| Upstream allowlist | `ps.air-outer.com,.openai.com` | `ps.air-outer.com,.anthropic.com` |
| Body ceiling variable | `CODEX_PROXY_MAX_BODY_BYTES` | `CLAUDE_PROXY_MAX_BODY_BYTES` |

Everything else — target parsing, the signed relay envelope, header hygiene,
redirect rewriting, bounded bodies, error mapping, fail-closed relay
configuration — is identical, and is covered by this package's own tests.

Rewriting the client's `user-agent`, `anthropic-version`, `anthropic-beta` or
`x-api-key` would replace correct identity with a guess, and injecting a body
field would corrupt a request the client composed itself. So this Worker
supplies no `projectRequest` at all; headers and body go upstream as sent, minus
only the headers that must never travel (below).

## Request URL

The first path segment is the upstream hostname. The remaining path and query
are preserved, and the upstream scheme is always HTTPS:

```text
https://claude.example.com/api.anthropic.com/v1/messages
→ https://api.anthropic.com/v1/messages
```

A hostname-only target is valid and resolves to `/`.

Rejected with `400 invalid_target`: non-HTTPS schemes, credentials, explicit
ports, IP literals, `localhost`, malformed hostnames, and a first segment that
disagrees with the parsed hostname. IP literals and loopback names are refused
here as well as by the relay's post-DNS SSRF policy — the edge check keeps
requests that must always fail from consuming relay capacity.

## Client authentication

There is none. The Worker is an open endpoint by design: point Claude Code's
base URL at it and it works, with no Worker-specific credential and no custom
headers.

```bash
curl --request POST \
  --url 'https://claude.example.com/api.anthropic.com/v1/messages' \
  --header 'x-api-key: <your own Anthropic key>' \
  --header 'anthropic-version: 2023-06-01' \
  --header 'Content-Type: application/json' \
  --data '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[]}'
```

The only credential involved is the caller's own `x-api-key`, forwarded
untouched. The Worker holds no shared upstream key, so a caller can never spend
someone else's quota.

Two properties are deliberately retained despite the open ingress:

- Every client-supplied `x-codex-relay-*` request header is stripped before
  egress (`src/headers.ts`), so an open caller still cannot forge the
  Worker→relay envelope or its result attribution.
- `ALLOWED_UPSTREAM_HOSTS` bounds *what* an open caller can reach. Being open to
  callers is acceptable; being an open proxy to arbitrary hosts is not, because
  the traffic egresses from the relay's VPS address and abuse is attributed
  there.

| Condition | Status | `type` |
| --- | --- | --- |
| Target host not in `ALLOWED_UPSTREAM_HOSTS` | `400` | `invalid_target` |
| Upstream redirect to a non-allowed host | `502` | `invalid_upstream_redirect` |

A rejected target fails closed before the body is read and before any egress, so
a disallowed request consumes no relay capacity.

## Relay protocol

The Worker signs each request and posts it to the fixed relay endpoint. Method,
target, and business headers travel as control headers, so the relay verifies
the exact bytes that were signed:

```text
POST <EGRESS_RELAY_URL>
x-codex-relay-version      1
x-codex-relay-key-id       <key id>
x-codex-relay-timestamp    <unix seconds>
x-codex-relay-nonce        <base64url, 16 random bytes>
x-codex-relay-method       <business method>
x-codex-relay-target       <base64url absolute https URL>
x-codex-relay-headers      <base64url canonical header block>
x-codex-relay-body-sha256  <base64url SHA-256 of body>
x-codex-relay-signature    <base64url HMAC-SHA256 over the canonical request>
```

The `x-codex-relay-` prefix is the wire protocol's name, shared with the Rust
relay and the Codex Worker; it is not Codex-specific behaviour.

The canonical request and its encoding are frozen by a language-independent
fixture, so a change on either side that breaks compatibility fails the other
side's tests:

```text
test/fixtures/relay-protocol-v1.json
```

The relay verifies the signature, rejects a stale timestamp or a replayed nonce,
re-derives the upstream request from the signed block, and streams the response
back.

### Header hygiene

`x-api-key`, `anthropic-version`, `anthropic-beta`, `Content-Type`, `Accept` and
the client's `user-agent` are signed and reach the upstream. Three groups never
do:

- request hop-by-hop and framing headers (`connection`, `content-length`,
  `host`, `transfer-encoding`, …), which describe a connection the relay does
  not reuse;
- source-revealing headers (`cf-connecting-ip`, `cf-ray`, `cf-visitor`,
  `cdn-loop`, `forwarded`, `x-forwarded-*`, `true-client-ip`, `x-real-ip`, …),
  which would hand the upstream the real client IP and defeat the relay;
- anything under the `x-codex-relay-` prefix, so a client cannot forge an
  envelope field or its result attribution. With no ingress credential in front
  of the Worker, this prefix rule is the only thing standing between an open
  caller and a forged relay envelope.

## Redirects

The relay does not follow redirects. A 3xx therefore arrives with the upstream's
own `Location`, which the Worker rewrites onto its own dynamic-target route so a
redirect-following client stays on the relay path:

```text
Location: https://target.example/next
→ Location: https://claude.example.com/target.example/next
```

`Location` is resolved against the original target as base, so relative,
root-relative, and protocol-relative forms all work. Query strings survive;
fragments are dropped because they never reach a server.

A `Location` that could not have been requested directly — non-HTTPS, opaque
scheme, credentials, explicit non-default port, invalid hostname, empty, or
containing CR/LF/tab — returns `502 invalid_upstream_redirect`. It is never
passed through, because that would take the client off the relay path.

## Limits and error mapping

| Condition | Status | `type` |
| --- | --- | --- |
| Invalid target path | `400` | `invalid_target` |
| Unreadable request body | `400` | `upstream_error` |
| Body over the limit | `413` | `request_too_large` |
| Relay config missing or malformed | `502` | `relay_unavailable` |
| Relay call failed | `502` | `relay_unavailable` |
| Unsafe upstream `Location` | `502` | `invalid_upstream_redirect` |
| Relay at capacity | `503` | `relay_busy` |
| Upstream timed out | `504` | `upstream_timeout` |

Request-body limit: 10 MiB (`CLAUDE_PROXY_MAX_BODY_BYTES`), matching the relay's
own limit. The relay caps responses at 64 MiB and applies a 30-second
response-header timeout.

Client-facing errors are generic by design. Relay hostnames, the signing secret,
and upstream error text never appear in a response body.

Response bodies stream: SSE events reach the client as they arrive, and
`content-encoding` is preserved because neither the Worker nor the relay
decompresses or re-encodes.

## Configuration

Required:

```text
EGRESS_RELAY_URL      absolute https:// URL ending in /v1/forward
EGRESS_RELAY_KEY_ID   key id the relay resolves to a secret
EGRESS_RELAY_SECRET   Worker secret; HMAC signing key
```

Optional:

```text
ALLOWED_UPSTREAM_HOSTS    comma-separated upstream hostname allowlist
CLAUDE_PROXY_MAX_BODY_BYTES  request body ceiling in bytes
```

`ALLOWED_UPSTREAM_HOSTS` is matched case-insensitively against the exact
hostname; a leading dot (`.anthropic.com`) also matches subdomains, and the
parent domain itself. There are no wildcards, and a suffix entry cannot match a
sibling domain (`.anthropic.com` does not match `evil-anthropic.com`). The same
rule is applied to upstream redirects, so a redirect cannot reach a host a
client could not have requested directly.

`wrangler.toml` holds only the non-secret URL and key id, so a deploy cannot
silently lose them. The signing secret is set out of band and appears in no
committed file:

```bash
npx wrangler secret put EGRESS_RELAY_SECRET
```

This **must be the same secret the Codex Worker uses**: both sign against the
relay's `w-20260820` key. The shared key means no relay-side change and no
service restart, at the cost that the relay cannot tell the two Workers apart,
so neither can be revoked or rate-limited independently. Splitting them later
means adding a key to the relay's config and restarting it.

## Development

Requirements: Node.js 22+, npm, Wrangler.

```bash
npm ci
npm run check   # tsc --noEmit && vitest run && wrangler deploy --dry-run
```

CI runs the same `npm ci` + `npm run check` gate as its own job, independent of
the Codex Worker's.

## Deployment

```bash
npx wrangler deploy
```

Deployed as `claude-worker-relay`. `workers_dev` and `preview_urls` are both
`false` so a deploy cannot resurrect a `workers.dev` hostname or preview URL
alongside the dashboard-managed custom domain.

Deploy order matters when relay changes are involved: relay first, then Workers.
A Worker signing against a key the relay does not yet know fails closed.
