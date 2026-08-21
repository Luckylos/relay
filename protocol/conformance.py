#!/usr/bin/env python3
"""Cross-language conformance gate for relay protocol v1.

Why this exists
---------------
The wire protocol is implemented three times: `relay-server/relay_protocol.rs`
(Rust server), `worker/src/relay/{protocol,signing}.ts` (Cloudflare Worker) and
`relay-server/scripts/relay_probe.py` (operator probe). Before the monorepo they
lived in separate repositories with a hand-copied fixture, so an edit to one side
could silently break HMAC verification with nothing turning red.

This gate drives all three implementations over the SAME generated vectors and
requires byte-identical canonical requests and signatures. It is the structural
replacement for "remember to copy the fixture".

Vectors deliberately cover the cases where the three languages disagree by
default:

- ASCII vs locale collation of header names (`-` is collation-ignorable in ICU,
  so `localeCompare` can disagree with byte ordering).
- Whitespace folding: Python's `str.split()` folds NBSP/FF/VT, while the spec
  (docs/https-relay-design-v1.md §5.2) folds only SPACE and TAB.
- Non-ASCII targets, which must be signed as UTF-8 bytes.
- Empty bodies and empty header sets.

Usage
-----
    python3 protocol/conformance.py            # run the gate
    python3 protocol/conformance.py --emit     # print vectors as JSON

Exit code is non-zero on any mismatch, so CI can gate on it directly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The canonical fixture, plus the per-subtree copies each side reads.
#
# The copies are deliberate: `worker/` and `relay-server/` must each stay
# independently extractable and runnable, so neither may read across subtree
# boundaries. Byte-identity is therefore a gated invariant rather than a
# filesystem fact.
CANONICAL_FIXTURE = ROOT / "protocol" / "relay-protocol-v1.json"
FIXTURE_COPIES = (
    ROOT / "relay-server" / "tests" / "fixtures" / "relay-protocol-v1.json",
    ROOT / "worker" / "test" / "fixtures" / "relay-protocol-v1.json",
)


def check_fixture_copies() -> int:
    """Require every subtree's fixture to match the canonical bytes exactly."""
    if not CANONICAL_FIXTURE.is_file():
        print(f"FAIL: canonical fixture missing at {CANONICAL_FIXTURE}")
        return 1

    canonical = CANONICAL_FIXTURE.read_bytes()
    digest = hashlib.sha256(canonical).hexdigest()
    print(f"canonical fixture sha256={digest}")

    failures = 0
    for copy in FIXTURE_COPIES:
        relative = copy.relative_to(ROOT)
        if not copy.is_file():
            print(f"FAIL {relative}: missing")
            failures += 1
            continue
        if copy.read_bytes() != canonical:
            print(
                f"FAIL {relative}: drifted from protocol/relay-protocol-v1.json "
                f"(sha256={hashlib.sha256(copy.read_bytes()).hexdigest()})"
            )
            failures += 1
            continue
        print(f"ok   {relative}")

    return failures

SECRET = "conformance-secret-not-a-real-key"
NONCE = base64.urlsafe_b64encode(bytes(range(16))).decode().rstrip("=")


def vectors() -> list[dict]:
    """Generated vectors, ordered so a failure names the property it broke."""
    return [
        {
            "name": "frozen-fixture-parity",
            "key_id": "w-20260820",
            "timestamp": 1755000000,
            "method": "POST",
            "target": "https://api.openai.com/v1/responses?stream=true",
            "headers": [
                ["Authorization", "Bearer redacted"],
                ["Content-Type", "application/json"],
                ["Accept", "text/event-stream"],
            ],
            "body_utf8": '{"model":"gpt-5","stream":true}',
        },
        {
            # `x-b` vs `xa`: ICU primary strength treats `-` as ignorable, so a
            # locale collator can order these differently from bytes.
            "name": "ascii-order-hyphen-vs-letter",
            "key_id": "k1",
            "timestamp": 1755000001,
            "method": "GET",
            "target": "https://example.com/",
            "headers": [
                ["x-b", "1"],
                ["xa", "2"],
                ["x-a", "3"],
                ["x--a", "4"],
            ],
            "body_utf8": "",
        },
        {
            # Digits sort before letters in ASCII; some collations disagree.
            "name": "ascii-order-digits-before-letters",
            "key_id": "k1",
            "timestamp": 1755000002,
            "method": "GET",
            "target": "https://example.com/",
            "headers": [
                ["x-9", "nine"],
                ["x-a", "a"],
                ["9x", "leading-digit"],
                ["a1", "a1"],
                ["a-1", "a-1"],
            ],
            "body_utf8": "",
        },
        {
            # Only SPACE and TAB fold. NBSP (U+00A0), form feed and vertical tab
            # must survive verbatim, which is where `str.split()` diverges.
            "name": "whitespace-folds-space-and-tab-only",
            "key_id": "k1",
            "timestamp": 1755000003,
            "method": "PUT",
            "target": "https://example.com/x",
            "headers": [
                ["x-spaces", " \talpha\t  beta   gamma \t"],
                ["x-nbsp", "alpha\u00a0beta"],
                ["x-formfeed", "alpha\u000cbeta"],
                ["x-vtab", "alpha\u000bbeta"],
                ["x-emspace", "alpha\u2003beta"],
            ],
            "body_utf8": "body",
        },
        {
            "name": "non-ascii-target-utf8",
            "key_id": "k1",
            "timestamp": 1755000004,
            "method": "POST",
            "target": "https://\u4f8b\u3048.\u30c6\u30b9\u30c8/v1/\u8def\u5f84?q=\u96ea",
            "headers": [["accept", "application/json"]],
            "body_utf8": "\u96ea",
        },
        {
            "name": "empty-headers-and-body",
            "key_id": "k1",
            "timestamp": 1755000005,
            "method": "DELETE",
            "target": "https://example.com/gone",
            "headers": [],
            "body_utf8": "",
        },
    ]


def payload() -> dict:
    return {"secret": SECRET, "nonce": NONCE, "vectors": vectors()}


def run(label: str, argv: list[str], cwd: pathlib.Path, stdin: str) -> dict:
    result = subprocess.run(
        argv, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=600
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"FAIL: {label} runner exited {result.returncode}")
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as error:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"FAIL: {label} runner emitted no JSON ({error})") from error


def run_ts(worker: pathlib.Path, stdin: str, scratch: str) -> dict:
    """Bundle then run the Worker's own protocol code on plain Node.

    `worker/src` uses extensionless imports (tsconfig moduleResolution:
    "Bundler"), which plain Node ESM cannot resolve. Bundling with the esbuild
    wrangler already ships keeps production import style untouched and still
    exercises the exact source the Worker deploys.
    """
    esbuild = worker / "node_modules" / ".bin" / "esbuild"
    if not esbuild.is_file():
        raise SystemExit(f"FAIL: esbuild missing at {esbuild} (run `npm ci` in worker/)")

    bundle = pathlib.Path(scratch) / "conformance.mjs"
    build = subprocess.run(
        [
            str(esbuild),
            "scripts/conformance.ts",
            "--bundle",
            "--format=esm",
            "--platform=node",
            "--target=node22",
            f"--outfile={bundle}",
        ],
        cwd=worker,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if build.returncode != 0:
        sys.stderr.write(build.stderr)
        raise SystemExit("FAIL: esbuild could not bundle the ts conformance runner")

    return run("ts", ["node", str(bundle)], worker, stdin)


def python_results(data: dict) -> dict:
    """Drive the operator probe's own canonicalization code."""
    sys.path.insert(0, str(ROOT / "relay-server" / "scripts"))
    import hashlib
    import hmac

    import relay_probe

    out = {}
    for vector in data["vectors"]:
        body = vector["body_utf8"].encode()
        block = relay_probe.canonical_headers(
            [(name, value) for name, value in vector["headers"]]
        )
        digest = relay_probe.b64u(hashlib.sha256(body).digest())
        canonical = relay_probe.canonical_request(
            vector["key_id"],
            vector["timestamp"],
            data["nonce"],
            vector["method"],
            vector["target"],
            digest,
            block,
        )
        signature = relay_probe.b64u(
            hmac.new(
                data["secret"].encode(), canonical.encode(), hashlib.sha256
            ).digest()
        )
        out[vector["name"]] = {"canonical": canonical, "signature": signature}
    return out


def compare(results: dict[str, dict]) -> int:
    reference_name = "rust"
    reference = results[reference_name]
    failures = 0

    for name in [vector["name"] for vector in vectors()]:
        row = {impl: results[impl].get(name) for impl in results}
        missing = [impl for impl, value in row.items() if value is None]
        if missing:
            print(f"FAIL {name}: missing results from {', '.join(missing)}")
            failures += 1
            continue

        canonicals = {impl: value["canonical"] for impl, value in row.items()}
        signatures = {impl: value["signature"] for impl, value in row.items()}
        agree = len(set(canonicals.values())) == 1 and len(set(signatures.values())) == 1

        if agree:
            print(f"ok   {name}  sig={signatures[reference_name][:16]}...")
            continue

        failures += 1
        print(f"FAIL {name}")
        for impl in sorted(canonicals):
            marker = "" if canonicals[impl] == reference["canonical"] else "  <-- differs"
            print(f"       {impl:6} sig={signatures[impl]}{marker}")
        for impl in sorted(canonicals):
            if canonicals[impl] != canonicals[reference_name]:
                print(f"       canonical[{reference_name}] = {canonicals[reference_name]!r}")
                print(f"       canonical[{impl}] = {canonicals[impl]!r}")
                break

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit", action="store_true", help="print the generated vectors as JSON"
    )
    args = parser.parse_args()

    data = payload()
    if args.emit:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    print("== relay protocol v1 fixture copies ==")
    fixture_failures = check_fixture_copies()
    print()

    stdin = json.dumps(data, ensure_ascii=False)

    with tempfile.TemporaryDirectory() as scratch:
        print("== relay protocol v1 cross-language conformance ==")
        results = {
            "rust": run(
                "rust",
                ["cargo", "run", "--quiet", "--bin", "conformance"],
                ROOT / "relay-server",
                stdin,
            ),
            "ts": run_ts(ROOT / "worker", stdin, scratch),
            "python": python_results(data),
        }

    failures = compare(results) + fixture_failures
    print()
    if failures:
        print(f"RESULT: {failures} conformance check(s) failed")
        return 1
    print(
        f"RESULT: all {len(vectors())} vectors agree across rust / ts / python; "
        f"{len(FIXTURE_COPIES)} fixture copies byte-identical"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
