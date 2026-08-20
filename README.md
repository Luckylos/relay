# codex-worker-relay

Standalone Cloudflare Worker relay for forwarding Codex-compatible HTTPS requests.

> **Current status:** direct Cloudflare `fetch()` egress and SOCKS5 proxy egress
> are both implemented and covered by tests. HTTP CONNECT proxies are **not**
> supported. When `EGRESS_PROXY_URL` is set, every request goes through the
> proxy or fails closed with `502`/`504` — the Worker never silently falls back
> to direct egress. End-to-end validation against a real upstream through a real
> SOCKS5 node is still outstanding; see *Verification status*.

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

## Proxy mode (SOCKS5)

Set `EGRESS_PROXY_URL` to route all upstream traffic through a SOCKS5 node:

```text
EGRESS_PROXY_URL=socks5://proxy.example:1080
EGRESS_PROXY_URL=socks5://user:pass@proxy.example:1080
```

`socks5h://` is accepted as an alias. It makes no difference here because
CONNECT always sends the upstream as `ATYP=DOMAIN`, so the proxy performs the
DNS resolution and the Worker never resolves the upstream itself.

The request path is:

```text
cloudflare:sockets connect(proxy, secureTransport: "starttls")
  → SOCKS5 method negotiation
  → RFC 1929 username/password auth (only when the URL carries credentials)
  → CONNECT upstream:443 with ATYP=DOMAIN
  → startTls({ expectedServerHostname: <upstream> })
  → HTTP/1.1 request, streamed response
```

TLS is terminated by the Cloudflare runtime against the **upstream** hostname,
not the proxy's. The proxy therefore sees only ciphertext and cannot present its
own certificate; a hostname mismatch fails the handshake. This was confirmed on
a real workerd runtime with a deliberate wrong-hostname negative control.

Any other scheme, including `http://`, is rejected — HTTP CONNECT is not
implemented. Unusable configuration fails closed before any egress:

```json
{
  "error": {
    "message": "configured proxy egress is unavailable",
    "type": "proxy_unavailable"
  }
}
```

Failure mapping, all without a direct-egress fallback:

| Condition | Status | `type` |
| --- | --- | --- |
| Unparseable URL or non-SOCKS5 scheme | `502` | `proxy_unavailable` |
| Dial, negotiation, auth, or TLS failure | `502` | `proxy_unavailable` |
| Handshake/TLS/response head past the deadline | `504` | `proxy_timeout` |

Client-facing errors are generic by design: proxy hostnames, credentials, and
handshake detail never appear in a response body. `CODEX_PROXY_TUNNEL_TIMEOUT_MS`
(default `120000`) bounds setup only — it does not bound the response body, so a
long-lived SSE stream is never truncated by it.

The URL carries credentials, so supply it as a Worker Secret:

```bash
wrangler secret put EGRESS_PROXY_URL
```

Percent-encode credentials containing `@`, `:`, or `/`. Never paste the value
into source, a committed `.env`, logs, or error responses. No proxy URL,
username, or password is present anywhere in this repository.

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

Proxy-related variables:

```text
EGRESS_PROXY_URL                 (Worker Secret; SOCKS5 only)
CODEX_PROXY_TUNNEL_TIMEOUT_MS    (default 120000, setup phase only)
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

## Verification status

Verified:

- `npm run check` (typecheck, full Vitest suite, Wrangler dry-run build);
- SOCKS5 negotiation, RFC 1929 auth, and `ATYP=DOMAIN` CONNECT framing against
  in-memory socket fixtures, including fragmented replies;
- HTTP/1.1 status/header parsing with `content-length`, chunked, and
  close-delimited framing, plus a streaming test proving SSE events surface
  before the response ends;
- Worker-level wire-up: proxy dialled from `EGRESS_PROXY_URL`, TLS validated
  against the upstream hostname, identity projection preserved on the proxy
  path, generic credential-free errors, and no direct fallback on any failure;
- native `startTls()` after SOCKS5 CONNECT on a real workerd runtime, with a
  wrong-hostname negative control confirming certificate validation is active.

Not yet verified:

- end-to-end request through a real SOCKS5 node to a real upstream API,
  including SSE, from a deployed Worker.

An earlier capability spike concluded that Workers could not support proxy
tunnelling. That conclusion was wrong in its cause: the test proxy was not
reachable from Cloudflare's edge, and the TLS attempt used `node:tls`, which
cannot wrap a `cloudflare:sockets` socket. Native `startTls()` on a reachable
node works, which is what this implementation uses.
