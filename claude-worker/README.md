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

Both Workers project the caller's identity; what they project differs:

| | `codex-worker/` | `claude-worker/` (this package) |
| --- | --- | --- |
| Caller identity | **Synthesized Codex identity** in headers and `client_metadata`. | **Claude Code profile**, rebuilt from a pinned version. |
| Body | May receive injected `client_metadata` | Forwarded as-is except `metadata.user_id` |
| Body ceiling variable | `CODEX_PROXY_MAX_BODY_BYTES` | `CLAUDE_PROXY_MAX_BODY_BYTES` |

Everything else — target parsing, the signed relay envelope, header hygiene,
redirect rewriting, bounded bodies, error mapping, fail-closed relay
configuration — is identical, and is covered by this package's own tests. Both
Workers also deploy with an empty `ALLOWED_UPSTREAM_HOSTS`, so upstream reach is
no longer a difference between them either; see Configuration.

## Claude Code cloak

Every request is shaped into Claude Code form, with no caller-detection branch.
Trusting a caller's claim to be real Claude Code would make the presented
identity depend on a signal the caller controls, and forwarding one caller's
device and session identity while synthesizing another's puts several
inconsistent machines behind a single credential.

The profile is captured from the Bun-compiled `claude` native binary — CLI
2.1.239, SDK 0.112.1 — and pinned as one unit, because CLI version, SDK version
and beta set drift together between releases. Bumping one field alone yields a
combination that never shipped.

What the cloak rebuilds (`src/cloak/`):

| Concern | Behaviour |
| --- | --- |
| Identity headers | `user-agent`, `x-app`, the `X-Stainless-*` family and `anthropic-version` are deleted then rewritten from the profile. The caller's real `x-claude-code-*` / `x-claude-remote-*` session values are dropped. |
| `anthropic-beta` | Derived from the *transformed body*, so a beta is never announced without the field it describes. Unrecognised caller values are preserved at the tail. `count_tokens` gets its own profile. |
| Prompt content | **Not touched.** `system`, `tools`, `messages` and `thinking` are forwarded exactly as received. |
| `metadata.user_id` | A JSON *string* carrying `device_id` (64 hex), `account_uuid` (`""` for API-key auth, which is what a real client sends) and `session_id`, derived deterministically from the caller's key so one key is one stable device. |

Never touched: `x-api-key` and `authorization`. Upstream authorization stays the
caller's own, and this Worker holds no credential to substitute.

### Why the prompt is left alone

An earlier revision synthesized content: it prepended the Claude Code identity
line, appended a `# currentDate` reminder, inserted a `clear_thinking_20251015`
edit and planted cache breakpoints. That was wrong on three counts.

- A block unshifted onto the head of `system` shifts the whole prompt prefix, so
  the caller's own prompt cache misses — and a reminder carrying today's date
  re-misses every midnight. The breakpoints added alongside could not repair
  damage they were causing.
- `clear_thinking_20251015` tells the API to drop thinking blocks: silent data
  loss on a multi-turn request that owns its thinking history.
- An identity line and a date reminder change what the model answers. A relay
  that alters responses is not transparent, whatever its headers say.

There is also no disguise to be had. Real Claude Code sends a large situated
system prompt — tool inventory, working directory, git state — that differs on
every request. One fixed sentence approximates none of it; it produces a request
resembling neither a real client nor an honest API caller, and bills the caller
tokens for the confusion. The envelope is where this cloak can be accurate, so
that is where it stops.

The transform is idempotent — `transform(transform(x)) === transform(x)` — so a
request crossing more than one hop converges. It holds by construction now that
nothing is inserted: `metadata.user_id` is derived from the caller's key, so a
second pass rewrites it to the value it already held.

Scope: application layer only. The relay reaches upstream with rustls over
HTTP/2, so the TLS ClientHello, HTTP/2 settings and resulting JA4 are the
relay's, not a real client's — no amount of header work changes that. Billing
attribution (CCH and its signed headers) is excluded by decision, so requests
are shaped like Claude Code without claiming its billing identity.

Overrides, for a version bump without a code change:

```text
CLAUDE_CLOAK_CLI_VERSION      CLI version in the user-agent
CLAUDE_CLOAK_SDK_VERSION      X-Stainless-Package-Version
CLAUDE_CLOAK_RUNTIME_VERSION  X-Stainless-Runtime-Version
CLAUDE_CLOAK_OS               X-Stainless-OS
CLAUDE_CLOAK_ARCH             X-Stainless-Arch
CLAUDE_CLOAK_IDENTITY_SALT    domain separator for derived identity
```

These are operator variables, deliberately not caller-controlled: letting a
request choose its own version fields would let any caller invent an
inconsistent client, which is the failure the pinned profile prevents. `OS` and
`arch` default to Linux/x64 because that is what the egress host actually is — a
request leaving a Linux VPS while claiming MacOS/arm64 asserts a machine that is
not there.

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
untouched — the cloak rebuilds the client profile around it but never replaces
it. The Worker holds no shared upstream key, so a caller can never spend someone
else's quota.

Two properties are deliberately retained despite the open ingress:

- Every client-supplied `x-codex-relay-*` request header is stripped before
  egress (`src/headers.ts`), so an open caller still cannot forge the
  Worker→relay envelope or its result attribution.
- `ALLOWED_UPSTREAM_HOSTS` can bound *what* an open caller reaches, but the
  deployed value is empty: any public HTTPS host is reachable. That is a
  deliberate operator decision, and it means abuse of this Worker egresses from
  the relay's VPS address and is attributed there. Target *shape* is still
  enforced — HTTPS only, hostname only, no IP literals, no `localhost`.

The rules below apply whenever a list *is* configured; with the allowlist empty
only the redirect row's non-host checks can fire:

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

`x-api-key`, `Content-Type` and the cloak's rebuilt identity headers
(`anthropic-version`, `anthropic-beta`, `user-agent`, `x-app`, `X-Stainless-*`)
are signed and reach the upstream. Three groups never do:

- request hop-by-hop and framing headers (`connection`, `content-length`,
  `host`, `transfer-encoding`, …), which describe a connection the relay does
  not reuse;
- source-revealing headers — **every** `cf-` header by prefix, plus `cdn-loop`,
  `forwarded`, `x-forwarded-*`, `true-client-ip`, `x-real-ip`, … — which would
  hand the upstream the real client IP and defeat the relay. The prefix rule is
  the rule and the named list is documentation: `cf-pseudo-ipv4` reached a real
  upstream through this Worker because it was added to the platform after the
  list was written, and Cloudflare can introduce another at any time;
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

The deployed value is empty, which permits every public HTTPS host:

```text
ALLOWED_UPSTREAM_HOSTS = ""
```

That is an accepted trade-off for this deployment, not an oversight: the
integration test asserts the binding is empty, so the open contract cannot be
narrowed by accident — and the enforcement code plus its unit tests remain in
place, so re-narrowing is a one-value change:

```text
ALLOWED_UPSTREAM_HOSTS = "ps.air-outer.com,.anthropic.com"
```

When a list is set it is matched case-insensitively against the exact hostname;
a leading dot (`.anthropic.com`) also matches subdomains, and the parent domain
itself. There are no wildcards, and a suffix entry cannot match a sibling domain
(`.anthropic.com` does not match `evil-anthropic.com`). The same rule is applied
to upstream redirects, so a redirect cannot reach a host a client could not have
requested directly.

Understand what empty costs: this Worker is reachable by anyone and can be
pointed at any public HTTPS host, with egress attributed to the relay's address.
Set a list before sharing the endpoint.

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
