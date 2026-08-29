# egress-relay

Signed dynamic HTTPS egress for the Cloudflare Workers in `../codex-ingress` and
`../claude-ingress`. Each Worker holds its own caller-facing contract; this relay
is the network egress behind both and is never addressed by clients directly.

```
Worker → codex-https-relay :18093 → upstream (dynamic HTTPS target)
```

The crate is `egress-relay`; the deployed binary and systemd unit are still named
`codex-https-relay`. That name is a deploy identity, not a description — renaming
it would mean a new unit, a new binary path, and a cutover window on a host that
also carries the proxy egress and the Cloudflare tunnel, so it stays as is.

## Why it exists

A Cloudflare Worker cannot control its own TLS fingerprint: `fetch()` egresses
through Cloudflare's stack from a shared edge address. Two properties therefore
require a relay of our own:

1. **TLS fingerprint** — the ClientHello must match the real client a gated
   upstream expects. See `src/egress/tls.rs`.
2. **Stable egress address** — a fixed VPS address rather than a rotating pool
   of shared edge addresses.

The relay accepts only HMAC-signed envelopes from a known Worker key, so opening
the Worker's ingress does not open this egress.

## TLS fingerprint (`src/egress/tls.rs`)

rustls 0.23 backed by the **aws-lc-rs** provider, not `ring`. `ring` omits the
`ecdsa_secp521r1_sha512` (0x0603) signature algorithm, which was the sole JA4
mismatch against a captured genuine client ClientHello. `Cargo.toml` pins the
`*-no-provider` reqwest feature so `ring` is never linked in; changing that
feature silently changes the fingerprint.

ALPN offers `h2` then `http/1.1`, keeping the JA4 ALPN marker `h2`.

Response bodies are relayed byte-for-byte: `default-features = false` disables
automatic gzip/deflate/brotli so no `accept-encoding` is injected.

## Request identity

Identity projection is **not** in this crate. It lives in each Worker as a single
owner, so headers and body cannot drift apart across two language
implementations. The relay forwards what the Worker signed, unmodified.

- The Codex Worker (`../codex-ingress/src/identity.ts`) projects one resolved
  identity into both headers and the body's `client_metadata`, pinned to the
  Codex CLI `0.149.0` profile.
- The Claude Worker (`../claude-ingress/src/cloak/`) rebuilds the client profile
  headers and `anthropic-beta` from a pinned Claude Code profile, and leaves the
  caller's prompt content untouched.

Neither Worker substitutes the caller's upstream credential.

## Wire protocol generations (v1 and v2)

The relay reads both live generations, because it and the two Workers deploy
independently and there is no moment when all three change at once.

| | v1 | v2 (current) |
| --- | --- | --- |
| Control headers | `x-codex-relay-*` | `x-egress-relay-*` |
| Signing domain (canonical line 1) | `codex-relay-v1` | `egress-relay-v2` |
| Fixture | `tests/fixtures/relay-protocol-v1.json` | `tests/fixtures/relay-protocol-v2.json` |

Only line 1 of the canonical request differs; every other field, order, and
encoding is byte-for-byte identical. v1 is frozen, not retired.

Three rules keep the window from becoming an attack surface:

- **One generation per request.** `detect_generation` picks the namespace once
  from the header names present; every envelope field is then read from that
  namespace only. A request carrying both prefixes is refused
  `400 relay_duplicate_control` rather than resolved — per-field fallback would
  let a caller mix a v1 signature with a v2 target.
- **Both namespaces are stripped from the signed business-header block.** A
  forwarded header named under either prefix is refused, even though the block is
  signed: replaying it upstream would let a signed request forge attribution.
- **Every response is stamped in both namespaces.** `result`, `error`, and
  `request-id` are written under `x-egress-relay-*` and `x-codex-relay-*` with the
  same values and a single generated request id. A response carries no generation
  hint of its own, so stamping only one namespace would make an ingress that reads
  the other fail closed on every request. Upstream copies of all six names are
  deleted before stamping, so upstream cannot forge attribution in either
  generation.

`docs/relay-protocol-v2-delta.md` in the repository root records the full delta
and the deploy order it implies (relay first, then the Workers).

## Configuration (environment)

Read by `src/bin/relay_config.rs`; a missing or empty value falls back to a default,
while an invalid value or `0` fails startup rather than silently degrading.

| Variable | Purpose |
| --- | --- |
| `CODEX_RELAY_LISTEN_ADDR` | Bind address |
| `CODEX_RELAY_CURRENT_KEY_ID` / `CODEX_RELAY_CURRENT_SECRET` | Active signing key |
| `CODEX_RELAY_PREVIOUS_KEY_ID` / `CODEX_RELAY_PREVIOUS_SECRET` | Rotation slot; both or neither |
| `CODEX_RELAY_MAX_BODY_BYTES` | Request body ceiling |
| `CODEX_RELAY_MAX_RESPONSE_BYTES` | Response body ceiling |
| `CODEX_RELAY_MAX_CONCURRENCY` | Admission control; returns `503 relay_busy` when saturated |
| `CODEX_RELAY_CLOCK_SKEW_SECS` | Signature freshness window |
| `CODEX_RELAY_CONNECT_TIMEOUT_SECS` | TCP connect budget |
| `CODEX_RELAY_RESPONSE_HEADER_TIMEOUT_SECS` | Time to first response header |
| `CODEX_RELAY_STREAM_STALL_TIMEOUT_SECS` | Max gap between stream chunks |

## Build, test, run

```bash
cargo build --release --bin codex-https-relay
cargo test
cargo clippy --all-targets -- -D warnings
```

Cross-language protocol agreement is gated separately by
`../protocol/conformance.py`, which drives the `conformance` bin. Change the
envelope format and that gate must be regenerated deliberately, not adjusted to
pass.

## Deployment

`systemd/codex-https-relay.service` records the live deployment path
(`/opt/codex-https-relay`), which is not this repository's location. The unit
sets memory ceilings and a full filesystem/privilege sandbox because the host
also carries the proxy egress and the Cloudflare tunnel; a bad deploy here must
not take those down.

## Scope

This crate is egress only: signature verification, target validation, DNS SSRF
policy, TLS construction, and bounded forwarding. Caller-facing concerns —
ingress shape, upstream allowlist, identity projection, redirect rewriting —
belong to the Worker.
