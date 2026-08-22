# codex-relay

Monorepo for the HTTPS relay: two Cloudflare Worker ingresses and a Rust relay
server that share one versioned wire protocol.

```
codex-relay/
├── codex-worker/           Cloudflare Worker (TypeScript)  — Codex ingress
├── claude-worker/          Cloudflare Worker (TypeScript)  — Claude ingress
├── relay-server/           Rust binaries                   — VPS egress
├── protocol/               Canonical wire-protocol fixture + conformance gate
└── docs/                   Design and implementation plans
```

## Why one repository

The Workers and `relay-server/` implement two halves of the same signed
protocol. Kept in separate repositories, a change to canonicalization or signing
on one side could only be caught by hand-copying a fixture, and nothing turned
red when the copies drifted. Here they share one history, one fixture and one CI
run.

## Two Workers, not one with two entrypoints

`codex-worker/` and `claude-worker/` are separate packages that each carry their
own copy of the relay pipeline, signing, target and redirect code. They are
deployed as two distinct Cloudflare Workers, so each must be installable,
testable, buildable, deployable and **roll-back-able on its own** — a shared
source directory would have made one deploy able to break the other.

The duplication is the cost of that independence. Drift between the copies is
therefore the specific risk the conformance gate exists to catch: it drives
*both* TypeScript implementations, never one as a proxy for the other.

The only intended behavioural difference between them:

| | `codex-worker/` | `claude-worker/` |
| --- | --- | --- |
| Caller identity | **Synthesized.** Callers are not Codex, but the upstream channel expects Codex-shaped traffic, so one resolved identity is projected into `user-agent`, `originator`, `x-codex-*` headers **and** the body's `client_metadata` | **Forwarded untouched.** The caller really is Claude Code and already sends correct `user-agent`, `anthropic-version`, `anthropic-beta`, `x-api-key`; rewriting it would replace correct identity with a guess |
| Body | May gain `client_metadata` | Never modified |
| Body ceiling | `CODEX_PROXY_MAX_BODY_BYTES` | `CLAUDE_PROXY_MAX_BODY_BYTES` |
| Allowed upstreams | `ps.air-outer.com,.openai.com` | `ps.air-outer.com,.anthropic.com` |

Everything else — mandatory relay egress, signed envelopes, target validation,
header stripping, bounded bodies, redirect rewriting, error mapping — is
identical by design and gated by each package's own tests.

## Subtree independence (a hard constraint)

**No package depends on any other, and none depends on `protocol/` at build or
test time.** Each of `codex-worker/`, `claude-worker/` and `relay-server/` can be
extracted on its own and will typecheck, test and build.

Concretely:

- No source, test, config or build file reaches outside its own subtree.
- Each subtree keeps **its own copy** of the protocol fixture:
  - `relay-server/tests/fixtures/relay-protocol-v1.json`
  - `codex-worker/test/fixtures/relay-protocol-v1.json`
  - `claude-worker/test/fixtures/relay-protocol-v1.json`
- `protocol/relay-protocol-v1.json` is the canonical copy. Byte-identity with the
  three subtree copies is a **gated invariant**, not a filesystem fact.

That is the deliberate trade: physical sharing would couple the subtrees, so
consistency is enforced by a check that fails loudly instead.

Verify independence at any time:

```bash
cp -a codex-worker  /tmp/solo-codex  && (cd /tmp/solo-codex  && npm ci && npm run check)
cp -a claude-worker /tmp/solo-claude && (cd /tmp/solo-claude && npm ci && npm run check)
```

Note the runtime fail-closed behaviour is a separate matter: a **deployed**
Worker requires relay configuration and returns `502 relay_unavailable` without
it, by design (`docs/https-relay-design-v1.md`). It never falls back to
Cloudflare's own egress. Independent means *the code stands alone*, not *the
deployment silently degrades*.

## Development

```bash
# Rust relay server
cd relay-server
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Codex Worker
cd codex-worker
npm ci
npm run check          # typecheck + vitest (workerd) + wrangler dry-run

# Claude Worker
cd claude-worker
npm ci
npm run check

# Cross-language protocol conformance (needs both toolchains)
python3 protocol/conformance.py
```

## The conformance gate

The wire protocol is implemented four times:
`relay-server/src/protocol/signing.rs`,
`codex-worker/src/relay/{protocol,signing}.ts`,
`claude-worker/src/relay/{protocol,signing}.ts`, and
`relay-server/scripts/relay_probe.py`. `protocol/conformance.py` drives all four
over shared vectors and requires byte-identical canonical requests and HMAC
signatures.

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
cd codex-worker  && npx wrangler deploy
cd claude-worker && npx wrangler deploy
```

Both Workers sign against the same relay key id, so `EGRESS_RELAY_SECRET` must be
set to the **same value** in each (`npx wrangler secret put EGRESS_RELAY_SECRET`
from the package directory). The relay's `KeyRing` is keyed by id, so this needs
no relay-side change; the tradeoff is that the relay cannot tell the two Workers
apart and so cannot revoke or rate-limit them independently.

`relay-server/systemd/codex-https-relay.service` intentionally records the live
deployment path (`/opt/codex-https-relay`), which is not this repository's
location.
