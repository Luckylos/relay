# codex-worker-relay

Standalone Cloudflare Worker relay for forwarding Codex-compatible HTTPS requests.

> **Current status:** direct Cloudflare `fetch()` egress is implemented and tested.
> HTTP CONNECT and SOCKS5 egress are intentionally **not enabled**: the real
> Cloudflare Workers capability spike did not establish the required proxy-tunnel
> TLS/streaming path. If `EGRESS_PROXY_URL` is set, the Worker fails closed with
> `502 proxy_unavailable`; it never silently falls back to direct egress.

## Request URL

The first path segment is the upstream hostname. The remaining path and query
string are preserved, and the upstream scheme is always HTTPS:

```text
https://relay.example.com/api.openai.com/v1/responses?stream=true
→ https://api.openai.com/v1/responses?stream=true
```

A hostname-only target is also valid:

```text
https://relay.example.com/example.com
→ https://example.com/
```

There is no route table, per-domain egress configuration, or hostname allowlist
in this MVP. Do not expose this unauthenticated relay to an untrusted network;
the MVP intentionally does not add an entry-authentication layer or SSRF policy.

## Direct mode (implemented)

Leave `EGRESS_PROXY_URL` unset. The Worker uses the standard Cloudflare
`fetch()` API for every valid target:

```bash
curl --request POST \
  --url 'https://relay.example.com/api.openai.com/v1/responses?stream=true' \
  --header 'Authorization: Bearer <token>' \
  --header 'Content-Type: application/json' \
  --data '{"model":"gpt-5.6","stream":true}'
```

The upstream response preserves its status code, permitted response headers,
content encoding, and streaming body. `Connection`, `Transfer-Encoding`, and
other HTTP hop-by-hop response headers are removed because the Worker creates a
new downstream response.

## Proxy configuration (blocked / fail-closed)

The planned configuration forms are documented here for compatibility with the
frozen plan, but are not currently executable in this Worker build:

```text
EGRESS_PROXY_URL=http://proxy.example:8080
EGRESS_PROXY_URL=http://user:pass@proxy.example:8080
EGRESS_PROXY_URL=socks5://proxy.example:1080
EGRESS_PROXY_URL=socks5://user:pass@proxy.example:1080
```

If a proxy value is supplied, every request returns a sanitized response like:

```json
{
  "error": {
    "message": "configured proxy egress is unavailable",
    "type": "proxy_unavailable"
  }
}
```

No proxy URL, username, or password is written to the repository. A future
implementation must load the value from a Worker Secret, for example:

```bash
wrangler secret put EGRESS_PROXY_URL
```

Do not paste the secret into source, `.env` files committed to Git, logs, or
error responses. The `wrangler secret put` command is documentation only; this
repository does not deploy a working proxy adapter yet.

## Codex identity projection

The Worker ports the observable identity behavior from the Rust reference
implementation:

- canonical `user-agent`, `originator`, `session-id`, `thread-id`, request,
  window, installation, beta-feature, turn-metadata, and `accept-encoding`
  headers are projected consistently;
- genuine client-supplied Codex identity values are preserved;
- duplicate casing/alias variants are removed before one canonical value is set;
- JSON object bodies with `Content-Type: application/json` receive coherent
  `client_metadata` when it is absent;
- an existing `client_metadata` body is preserved byte-for-byte;
- `Authorization` and ordinary non-identity headers are forwarded;
- request and response hop-by-hop headers are removed.

The Worker does not send Rust-only `version` or `conversation_id` fields.

## Limits and runtime differences

- Default request-body limit: **10 MiB** (`CODEX_PROXY_MAX_BODY_BYTES`).
- Oversized request bodies return `413 request_too_large`.
- Invalid target paths return `400 invalid_target`.
- SSE and other response bodies are returned as Web Streams; the Worker does
  not wait for the complete upstream body before returning.
- `redirect: "manual"` preserves upstream redirect responses.
- The Worker cannot reproduce the Rust relay's `aws-lc-rs` JA4 or HTTP/2
  fingerprint. Cloudflare controls the Worker outbound TLS/runtime fingerprint.
- There is no entry authentication, allowlist, rate limit, quota, or SSRF/private
  target policy in this MVP. These are deployment risks, not implemented
  security controls.

## Configuration

`wrangler.toml` intentionally contains no proxy URL or credentials. Optional
bindings include:

```text
CODEX_PROXY_UA_VERSION
CODEX_PROXY_ORIGINATOR
CODEX_PROXY_UA_OS
CODEX_PROXY_UA_TERMINAL
CODEX_PROXY_USER_AGENT
CODEX_PROXY_BETA_FEATURES
CODEX_PROXY_INSTALLATION_ID
CODEX_PROXY_ACCEPT_ENCODING
CODEX_PROXY_MAX_BODY_BYTES
```

Set stable identity values through Worker variables/secrets appropriate to the
deployment. Keep credentials in permission-restricted secret storage.

## Development

Requirements: Node.js 22+, npm, and Wrangler.

```bash
npm ci
npm run check
```

`npm run check` runs:

```text
npm run typecheck
npm test
wrangler deploy --dry-run --outdir dist
```

The project has CI coverage for the same `npm ci` + `npm run check` gate.

## Cloudflare proxy capability decision

A temporary preview Worker was used to test the planned proxy path and was
removed after the spike. Verified observations:

- the Worker deployed and its health endpoint returned `200`;
- `cloudflare:sockets` is available, but direct socket access to an HTTPS HTTP
  origin on port 443 returned Cloudflare's documented disallowed-address/HTTP
  service error;
- the configured local HTTP/SOCKS5 test listener was not externally reachable
  from Cloudflare, so HTTP CONNECT, SOCKS5 CONNECT, target TLS/SNI, and tunneled
  SSE could not be proven on the real edge runtime;
- the temporary Worker was deleted and the Cloudflare API confirmed that the
  script no longer exists.

Per the frozen plan, this stops the pure-Worker proxy branch rather than
substituting direct mode for proxy mode. A future proxy implementation needs a
separately approved architecture and a reachable controlled test node.
