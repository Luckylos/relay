# codex-ingress

Cloudflare Worker front end for Codex-compatible HTTPS requests. Every upstream
request leaves through a signed HTTPS relay on a VPS, so the upstream sees the
VPS address rather than Cloudflare's.

```text
client → Worker → HTTPS relay (VPS) → dynamic HTTPS upstream:443
```

> **Status:** the Worker side is complete and covered by tests. The relay is a
> separate Rust service (`codex-https-relay`).
>
> **Package independence:** this directory is a standalone deployment
> artifact. It carries its own copy of the relay pipeline, signing and target
> code, so it installs, tests, builds and deploys without `claude-ingress/` or
> the repository root present. The Claude Worker carries its own copy; the two
> are kept byte-compatible by `protocol/conformance.py`, which drives both
> TypeScript implementations over the same vectors as the Rust relay.
> End-to-end validation against a deployed relay and a real upstream is still
> outstanding — see *Verification status*.

The relay is the **only** egress path. There is no direct-`fetch()` mode and no
proxy mode: an incomplete relay configuration fails the request instead of
falling back, because a fallback would send traffic from Cloudflare's address
space and defeat the reason the relay exists.

## Request URL

The first path segment is the upstream hostname. The remaining path and query
are preserved, and the upstream scheme is always HTTPS:

```text
https://worker.example.com/api.openai.com/v1/responses?stream=true
→ https://api.openai.com/v1/responses?stream=true
```

A hostname-only target is valid and resolves to `/`.

Rejected with `400 invalid_target`: non-HTTPS schemes, credentials, explicit
ports, IP literals, `localhost`, malformed hostnames, and a first segment that
disagrees with the parsed hostname. IP literals and loopback names are refused
here as well as by the relay's post-DNS SSRF policy — the edge check keeps
requests that must always fail from consuming relay capacity.

Which upstreams are reachable is governed by the optional
`ALLOWED_UPSTREAM_HOSTS` variable (see Configuration). **The deployed value is
empty by decision**, so any public HTTPS hostname is reachable and the relay's
DNS-time address policy is the only thing preventing private-range egress.

## Client authentication

There is none. The Worker is an open endpoint by design: point any
OpenAI-compatible client's base URL at it and it works, with no Worker-specific
credential and no custom headers.

```bash
curl --request POST \
  --url 'https://worker.example.com/api.openai.com/v1/responses?stream=true' \
  --header 'Authorization: Bearer ***' \
  --header 'Content-Type: application/json' \
  --data '{"model":"gpt-5.6","stream":true}'
```

The only credential involved is the caller's own upstream key in
`Authorization`, which is forwarded untouched. The Worker holds no shared
upstream key, so a caller can never spend someone else's quota.

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

The canonical request and its encoding are frozen by a language-independent
fixture shared with the Rust relay, so a change on either side that breaks
compatibility fails the other side's tests:

```text
test/fixtures/relay-protocol-v1.json
```

The relay verifies the signature, rejects a stale timestamp or a replayed nonce,
re-derives the upstream request from the signed block, and streams the response
back.

### Header hygiene

`Authorization`, `Content-Type`, `Accept`, and the Codex identity headers are
signed and reach the upstream. Three groups never do:

- request hop-by-hop and framing headers (`connection`, `content-length`,
  `host`, `transfer-encoding`, …), which describe a connection the relay does
  not reuse;
- source-revealing headers — **every** `cf-` header by prefix, plus `cdn-loop`,
  `forwarded`, `x-forwarded-*`, `true-client-ip`, `x-real-ip`, … — which would
  hand the upstream the real client IP and defeat the relay. The prefix rule is
  the rule and the named list is documentation: `cf-pseudo-ipv4` reached a real
  upstream because it was added to the platform after the list was written;
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
→ Location: https://worker.example.com/target.example/next
```

`Location` is resolved against the original target as base, so relative,
root-relative, and protocol-relative forms all work. Query strings survive;
fragments are dropped because they never reach a server.

A `Location` that could not have been requested directly — non-HTTPS, opaque
scheme, credentials, explicit non-default port, invalid hostname, empty, or
containing CR/LF/tab — returns `502 invalid_upstream_redirect`. It is never
passed through, because that would take the client off the relay path.

## Codex identity projection

The Worker ports the observable identity behavior of the Rust reference
implementation:

- canonical `user-agent`, `originator`, `session-id`, `thread-id`, request,
  window, beta-feature, and turn-metadata headers are projected consistently,
  pinned to the Codex CLI `0.149.0` profile;
- `x-client-request-id` and `x-codex-window-id` are derived from the thread id,
  matching `Session::current_window_id()`'s `{thread_id}:{window_number}`;
- `accept-encoding` and `x-codex-installation-id` are deliberately not sent on a
  main `/responses` turn: upstream never sets the former, and the latter is
  compaction-only. The installation id still travels in the body's
  `client_metadata`. Caller-supplied copies are stripped, not forwarded;
- turn metadata is serialized with non-ASCII escaped to `\uXXXX` so it is a
  valid header value;
- genuine client-supplied Codex identity values are preserved;
- duplicate casing/alias variants are removed before one canonical value is set;
- JSON object bodies with `Content-Type: application/json` receive coherent
  `client_metadata` when absent, and an existing `client_metadata` is preserved
  byte-for-byte;
- non-JSON, invalid-JSON, array, scalar, and untyped bodies pass through
  untouched.

The Worker does not send the Rust-only `version` or `conversation_id` fields.

## Limits and error mapping

| Condition | Status | `type` |
| --- | --- | --- |
| Invalid target path | `400` | `invalid_target` |
| Unreadable request body | `400` | `upstream_error` |
| Body over the limit | `413` | `request_too_large` |
| Relay config missing or malformed | `502` | `relay_unavailable` |
| Relay call failed | `502` | `relay_unavailable` |
| Unsafe upstream `Location` | `502` | `invalid_upstream_redirect` |
| Identity/body projection failed | `502` | `upstream_error` |

Request-body limit: 10 MiB (`CODEX_PROXY_MAX_BODY_BYTES`), matching the relay's
own limit. The relay caps responses at 64 MiB and applies a 30-second
response-header timeout.

Client-facing errors are generic by design. Relay hostnames, the signing secret,
and upstream error text never appear in a response body.

Response bodies stream: SSE events reach the client as they arrive, and
`content-encoding` is preserved because neither the Worker nor the relay
decompresses or re-encodes.

The Worker cannot reproduce the Rust relay's `aws-lc-rs` JA4 or HTTP/2
fingerprint — Cloudflare controls the Worker's own outbound TLS. That is
irrelevant on this path, because the TLS session the upstream sees is
established by the relay.

## Configuration

Required:

```text
EGRESS_RELAY_URL      absolute https:// URL ending in /v1/forward
EGRESS_RELAY_KEY_ID   key id the relay resolves to a secret
EGRESS_RELAY_SECRET   Worker secret; HMAC signing key
```

Optional:

```text
ALLOWED_UPSTREAM_HOSTS  comma-separated upstream hostname allowlist
```

`EGRESS_RELAY_SECRET` authenticates the Worker to the relay. It is never
accepted from, nor exposed to, a client: the `x-codex-relay-*` request-header
strip exists so an open caller cannot forge a signed envelope with it.

`ALLOWED_UPSTREAM_HOSTS` is matched case-insensitively against the exact
hostname; a leading dot (`.openai.com`) also matches subdomains, and the parent
domain itself. There are no wildcards, and a suffix entry cannot match a sibling
domain (`.openai.com` does not match `evil-openai.com`). The same rule is applied
to upstream redirects, so a redirect cannot reach a host a client could not have
requested directly.

The deployed value is empty, which permits every public HTTPS host:

```text
ALLOWED_UPSTREAM_HOSTS = ""
```

That is an accepted trade-off for this deployment, not an oversight: the
integration test asserts the binding is empty, so the open contract cannot be
narrowed by accident — and the enforcement code plus its unit tests remain in
place, so re-narrowing is a one-value change:

```text
ALLOWED_UPSTREAM_HOSTS = "ps.air-outer.com,.openai.com"
```

Understand what empty costs: this Worker is reachable by anyone and can be
pointed at any public HTTPS host, with egress attributed to the relay's address.
Set a list before sharing the endpoint.

`wrangler.toml` holds only the non-secret URL and key id, so a deploy cannot
silently lose them. The signing secret is set out of band and appears in no
committed file:

```bash
wrangler secret put EGRESS_RELAY_SECRET
```

Optional identity and limit bindings are listed in `.env.example`.

## Development

Requirements: Node.js 22+, npm, Wrangler.

```bash
npm ci
npm run check   # tsc --noEmit && vitest run && wrangler deploy --dry-run
```

CI runs the same `npm ci` + `npm run check` gate.

## Verification status

Verified:

- `npm run check`: typecheck, full Vitest suite, Wrangler dry-run build;
- relay protocol v1 signing against the shared fixture, byte-compatible with the
  Rust implementation;
- open ingress: no client credential required, and a client-supplied
  `x-codex-relay-*` header cannot forge the relay envelope;
- upstream allowlist: a disallowed target fails `400 invalid_target` with **zero**
  egress calls, checked before the body is read;
- header hygiene: platform and source-revealing headers stripped, relay control
  headers unforgeable, ingress token never forwarded;
- relay egress: signed envelope to the fixed endpoint, identity and body
  projection preserved, response streamed rather than buffered, `413` over the
  body limit, generic `502` on relay failure, and the signing secret absent from
  both client-visible errors and the outbound request;
- fail-closed routing: each missing relay variable yields `502` with no network
  call at all;
- redirect rewriting: relative/absolute/protocol-relative resolution, unsafe
  `Location` refused, and a rewritten `Location` that round-trips back through
  the Worker's own target parser;
- mutation testing on the redirect and target rules: every behaviour-changing
  mutant is detected.

Not yet verified:

- end-to-end request from a deployed Worker through a deployed relay to a real
  upstream API, including SSE, driven by a stock client with no custom headers.

A local adapter is no longer required: it existed only to inject the retired
`X-Codex-Relay-Token`, and clients now need nothing beyond a base URL.

## Deployment

```bash
npx wrangler deploy
```

Deployed as `codex-ingress-relay`. `workers_dev` and `preview_urls` are both
`false` so a deploy cannot resurrect a `workers.dev` hostname or preview URL
alongside the dashboard-managed custom domain.

Deploy order matters when relay changes are involved: relay first, then Workers.
A Worker signing against a key the relay does not yet know fails closed.

## History

Earlier revisions implemented direct Cloudflare `fetch()` egress and a SOCKS5
tunnel built on `cloudflare:sockets` + `startTls()`. Both are removed. The
SOCKS5 path worked on a real workerd runtime, but keeping the client's traffic
inside Cloudflare's address space was the wrong architecture for this service,
and maintaining a hand-rolled HTTP/1.1 client to do it was cost without benefit.
The design decision and rollout plan are recorded in `../docs/`.
