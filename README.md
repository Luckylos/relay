# codex-relay

Monorepo for the Codex HTTPS relay: a Cloudflare Worker ingress and a Rust relay
server that share one versioned wire protocol.

```
codex-relay/
├── worker/                 Cloudflare Worker (TypeScript)  — client ingress
├── relay-server/           Rust binaries                   — VPS egress
├── protocol/               Canonical wire-protocol fixture + conformance gate
└── docs/                   Design and implementation plans
```

## Why one repository

`worker/` and `relay-server/` implement two halves of the same signed protocol.
Kept in separate repositories, a change to canonicalization or signing on one
side could only be caught by hand-copying a fixture, and nothing turned red when
the copies drifted. Here they share one history, one fixture and one CI run.

## Subtree independence (a hard constraint)

**`worker/` does not depend on `relay-server/`, and neither depends on
`protocol/` at build or test time.** The relay server is an optional extension:
you can extract `worker/` on its own and it will typecheck, test and build.

Concretely:

- No source, test, config or build file reaches outside its own subtree.
- Each subtree keeps **its own copy** of the protocol fixture:
  - `relay-server/tests/fixtures/relay-protocol-v1.json`
  - `worker/test/fixtures/relay-protocol-v1.json`
- `protocol/relay-protocol-v1.json` is the canonical copy. Byte-identity with the
  two subtree copies is a **gated invariant**, not a filesystem fact.

That is the deliberate trade: physical sharing would couple the subtrees, so
consistency is enforced by a check that fails loudly instead.

Verify independence at any time:

```bash
cp -a worker /tmp/solo && cd /tmp/solo && npm ci && npm run check
```

Note the runtime fail-closed behaviour is a separate matter: a **deployed**
Worker requires relay configuration and returns `502 relay_unavailable` without
it, by design (`docs/https-relay-design-v1.md`). It never falls back to
Cloudflare's own egress. Optional means *the code stands alone*, not *the
deployment silently degrades*.

## Development

```bash
# Rust relay server
cd relay-server
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Cloudflare Worker
cd worker
npm ci
npm run check          # typecheck + vitest (workerd) + wrangler dry-run

# Cross-language protocol conformance (needs both toolchains)
python3 protocol/conformance.py
```

## The conformance gate

The wire protocol is implemented three times: `relay-server/relay_protocol.rs`,
`worker/src/relay/{protocol,signing}.ts`, and `relay-server/scripts/relay_probe.py`.
`protocol/conformance.py` drives all three over shared vectors and requires
byte-identical canonical requests and HMAC signatures.

Vectors target the places where the three languages disagree *by default*:

| Vector | Guards against |
| --- | --- |
| `frozen-fixture-parity` | Regression against the committed fixture |
| `ascii-order-hyphen-vs-letter` | Locale collation treating `-` as ignorable, so `localeCompare` disagrees with byte order |
| `ascii-order-digits-before-letters` | Collations that don't sort digits before letters |
| `whitespace-folds-space-and-tab-only` | Folding NBSP/FF/VT — spec §5.2 folds only SPACE and TAB |
| `non-ascii-target-utf8` | Targets signed as anything other than UTF-8 bytes |
| `empty-headers-and-body` | Empty header block / zero-length body encoding |

Two real defects were found and fixed this way: the Worker sorted header names
with `localeCompare` (locale-dependent, spec requires ASCII order), and the
Python probe folded all Unicode whitespace via `str.split()`.

## Deployment

The two artifacts deploy independently and the repository layout does not change
their paths. `relay-server/systemd/codex-https-relay.service` intentionally
records the live deployment path (`/opt/codex-https-relay`), which is not this
repository's location.
