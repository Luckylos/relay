# llm-egress-relay

Monorepo for the HTTPS relay: two Cloudflare Worker ingresses and a Rust relay
server that share one versioned wire protocol.

```
llm-egress-relay/
├── codex-ingress/           Cloudflare Worker (TypeScript)  — Codex ingress
├── claude-ingress/          Cloudflare Worker (TypeScript)  — Claude ingress
├── egress-relay/           Rust binaries                   — VPS egress
├── protocol/               Canonical wire-protocol fixtures + cross-subtree gates
└── docs/                   Design and implementation plans
```

## Why one repository

The Workers and `egress-relay/` implement two halves of the same signed
protocol. Kept in separate repositories, a change to canonicalization or signing
on one side could only be caught by hand-copying a fixture, and nothing turned
red when the copies drifted. Here they share one history, one fixture and one CI
run.

## Two Workers, not one with two entrypoints

`codex-ingress/` and `claude-ingress/` are separate packages that each carry their
own copy of the relay pipeline, signing, target and redirect code. They are
deployed as two distinct Cloudflare Workers, so each must be installable,
testable, buildable, deployable and **roll-back-able on its own** — a shared
source directory would have made one deploy able to break the other.

The duplication is the cost of that independence: shared authored files are
byte-identical between the two packages, so a fix has to land in both or one
Worker silently keeps the old behaviour. Two gates cover that risk:

- `protocol/shared_drift.py` requires every declared shared file to stay
  byte-identical, and
  requires every file in either package to be classified as shared, deliberately
  divergent (with the reason), or package-local. A new file fails the gate until
  it is classified, so an unguarded copy cannot be added by default.
- `protocol/conformance.py` covers the wire protocol more strongly still,
  driving *both* TypeScript implementations over shared vectors rather than one
  as a proxy for the other.

The files most exposed are the ones carrying security semantics — `pipeline.ts`
(fail-closed ordering), `target.ts` (SSRF policy) and `redirect.ts` (which keeps
callers from bypassing the relay) — where a one-sided edit is a one-sided
security regression.

The intended behavioural differences between them:

| | `codex-ingress/` | `claude-ingress/` |
| --- | --- | --- |
| Caller identity | **Synthesized.** Callers are not Codex, but the upstream channel expects Codex-shaped traffic, so one resolved identity is projected into `user-agent`, `originator`, `x-codex-*` headers **and** the body's `client_metadata` | **Rebuilt from a pinned profile.** A caller may or may not be Claude Code, so one profile is applied to every request: identity headers and `anthropic-beta` derived from the body. See `claude-ingress/src/cloak/` |
| Body | May gain `client_metadata` | Forwarded as-is except `metadata.user_id`; prompt content is never altered |
| Upstream credential | Caller's `Authorization`, forwarded untouched | Caller's `x-api-key`, forwarded untouched |
| Body ceiling | `CODEX_PROXY_MAX_BODY_BYTES` | `CLAUDE_PROXY_MAX_BODY_BYTES` |

Both projections are bounded the same way: they shape the request surface and
never the caller's upstream credential. Neither Worker holds a credential of its
own to substitute.

Both deploy with `ALLOWED_UPSTREAM_HOSTS = ""` — every public HTTPS host is
reachable, by decision. Each package's integration test asserts the binding is
empty so the open contract cannot be narrowed by accident, and the enforcement
code and its unit tests stay in place so re-narrowing is a one-value change.

Everything else — mandatory relay egress, signed envelopes, target validation,
header stripping, bounded bodies, redirect rewriting, error mapping — is
identical by design and gated by each package's own tests.

## Subtree independence (a hard constraint)

**No package depends on any other, and none depends on `protocol/` at build or
test time.** Each of `codex-ingress/`, `claude-ingress/` and `egress-relay/` can be
extracted on its own and will typecheck, test and build.

Concretely:

- No source, test, config or build file reaches outside its own subtree.
- Each subtree keeps **its own copy** of the protocol fixture, one per live
  protocol generation:
  - `egress-relay/tests/fixtures/relay-protocol-v{1,2}.json`
  - `codex-ingress/test/fixtures/relay-protocol-v{1,2}.json`
  - `claude-ingress/test/fixtures/relay-protocol-v{1,2}.json`
- `protocol/relay-protocol-v{1,2}.json` are the canonical copies. Byte-identity
  with the three subtree copies is a **gated invariant**, not a filesystem fact.
- v1 is frozen, not retired. Its fixture and signing domain stay exactly as
  shipped because a deployed v1 ingress can still be signing against them while
  the relay is already on v2.

That is the deliberate trade: physical sharing would couple the subtrees, so
consistency is enforced by a check that fails loudly instead.

Verify independence at any time:

```bash
cp -a codex-ingress  /tmp/solo-codex  && (cd /tmp/solo-codex  && npm ci && npm run check)
cp -a claude-ingress /tmp/solo-claude && (cd /tmp/solo-claude && npm ci && npm run check)
```

Note the runtime fail-closed behaviour is a separate matter: a **deployed**
Worker requires relay configuration and returns `502 relay_unavailable` without
it, by design (`docs/https-relay-design-v1.md`). It never falls back to
Cloudflare's own egress. Independent means *the code stands alone*, not *the
deployment silently degrades*.

## Failure response semantics

Relay attribution classifies a response that has already ended the current
upstream attempt; it does not recover or retry that attempt:

- `result=upstream` returns the upstream status, headers and body unchanged,
  including genuine upstream `4xx` and `5xx` responses. That attempt failed at
  the upstream and ends at the Worker.
- `result=error` maps the relay's machine code to the existing client-facing
  failure contract. That attempt also ends at the Worker.
- Missing or invalid attribution fails closed to `502 relay_unavailable`; it is
  not evidence by itself that either the relay or the target upstream caused the
  original failure.

The Worker has no retry or direct-egress fallback. Any whole-request retry or
channel failover belongs to its caller and must use an operation-aware policy.
There is no `599` carrier-status protocol in this repository: preserving failure
provenance across an intermediary would not make the failed attempt succeed, so
such an extension is justified only if measured caller behaviour depends on the
distinction.

## Development

```bash
# Rust relay server
cd egress-relay
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Codex Worker
cd codex-ingress
npm ci
npm run check          # typecheck + vitest (workerd) + wrangler dry-run

# Claude Worker
cd claude-ingress
npm ci
npm run check

# Shared-code byte identity between the two Workers (no toolchain needed)
python3 protocol/shared_drift.py
python3 protocol/shared_drift.py --verbose   # list every file and its category

# Cross-language protocol conformance (needs both toolchains)
python3 protocol/conformance.py
```

## The conformance gate

The wire protocol is implemented four times:
`egress-relay/src/protocol/signing.rs`,
`codex-ingress/src/relay/{protocol,signing}.ts`,
`claude-ingress/src/relay/{protocol,signing}.ts`, and
`egress-relay/scripts/relay_probe.py`. `protocol/conformance.py` drives all four
over shared vectors and requires byte-identical canonical requests and HMAC
signatures.

Every vector runs once per live protocol generation, so the table below is
exercised twice — under v1's `codex-relay-v1` signing domain and under v2's
`egress-relay-v2`. A runner that ignored a vector's `version` field would pass v1
while never signing a single v2 byte, which is why the generation is data and not
a global constant.

Vectors target the places where the languages disagree *by default*:

| Vector | Guards against |
| --- | --- |
| `frozen-fixture-parity` | Regression against the committed fixture |
| `ascii-order-hyphen-vs-letter` | Locale collation treating `-` as ignorable, so `localeCompare` disagrees with byte order |
| `ascii-order-digits-before-letters` | Collations that don't sort digits before letters |
| `whitespace-folds-space-and-tab-only` | Folding NBSP/FF/VT — spec §5.2 folds only SPACE and TAB |
| `non-ascii-target-utf8` | Targets signed as anything other than UTF-8 bytes |
| `empty-headers-and-body` | Empty header block / zero-length body encoding |

Two real defects were found and fixed this way: a Worker sorted header names with
`localeCompare` (locale-dependent, spec requires ASCII order), and the Python
probe folded all Unicode whitespace via `str.split()`.

## Deployment

The three artifacts deploy independently and the repository layout does not
change their paths.

```bash
cd codex-ingress  && npx wrangler deploy
cd claude-ingress && npx wrangler deploy
```

Both Workers sign against the same relay key id, so `EGRESS_RELAY_SECRET` must be
set to the **same value** in each (`npx wrangler secret put EGRESS_RELAY_SECRET`
from the package directory). The relay's `KeyRing` is keyed by id, so this needs
no relay-side change; the tradeoff is that the relay cannot tell the two Workers
apart and so cannot revoke or rate-limit them independently.

`egress-relay/systemd/codex-https-relay.service` intentionally records the live
deployment path (`/opt/codex-https-relay`), which is not this repository's
location.
