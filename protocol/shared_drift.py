#!/usr/bin/env python3
"""Byte-identity gate for the code both Worker packages carry.

Why this exists
---------------
`codex-ingress/` and `claude-ingress/` each hold their own byte-identical
copy of the shared relay plumbing declared below. The
duplication is deliberate and `protocol/conformance.py` already explains why --
each package must install, test, build, deploy and roll back on its own, which a
shared source directory would have prevented.

That decision moves a cost onto whoever edits those files: a fix has to land in
both copies or one Worker silently keeps the old behaviour. The files most
exposed to this are the ones carrying security semantics -- `src/pipeline.ts`
(fail-closed ordering), `src/target.ts` (SSRF policy) and `src/redirect.ts`
(which keeps callers from bypassing the relay). A one-sided edit there is a
one-sided security regression, and nothing in the repository turns red.

`conformance.py` states the principle -- "byte-identity is therefore a gated
invariant rather than a filesystem fact" -- but enforces it for the protocol
fixture implementations only. The remaining shared source, tests and toolchain
files would otherwise be held in sync by hand. Git history shows the discipline
has held so far: every shared file points at the same commit on both sides. This
gate is what keeps that true when it stops being remembered.

What it does NOT do
-------------------
It does not require the two packages to be identical. Each has code the other
must not carry -- `codex-ingress/src/identity.ts` projects an identity the Claude
ingress deliberately leaves alone, and `claude-ingress/src/cloak/` shapes Claude
Code requests the Codex ingress has no business emitting. Those live in
PACKAGE_LOCAL. Files that are shared but legitimately differ are listed in
INTENTIONALLY_DIVERGENT with the reason, and the gate checks each one still
differs -- an entry that has silently become identical is a stale exemption, and
that is reported too.

Adding a file to either package makes this gate fail until it is classified.
That is the point: the failure is the prompt to decide which of the three kinds
of file it is, rather than defaulting to an unguarded copy.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = ("codex-ingress", "claude-ingress")

# Directories that are build output or vendored code, not authored source.
SKIP_DIRS = frozenset({"node_modules", "dist", ".wrangler", ".git", "coverage"})

# Shared paths required to be byte-identical across both packages.
#
# Grouped by why drift there would hurt, because a failure should tell the
# reader what invariant broke rather than just naming a file.
SHARED_IDENTICAL: dict[str, tuple[str, ...]] = {
    "request policy (a one-sided edit is a one-sided security regression)": (
        "src/pipeline.ts",
        "src/target.ts",
        "src/redirect.ts",
        "src/headers.ts",
        "src/errors.ts",
    ),
    "relay wire protocol (also driven over shared vectors by conformance.py)": (
        "src/relay/protocol.ts",
        "src/relay/signing.ts",
        "src/relay/client.ts",
        "src/relay/config.ts",
        "src/relay/attribution.ts",
        "src/relay/control.ts",
        "src/relay/observability.ts",
    ),
    "tests for the shared code (drift here means one side stops checking it)": (
        "test/redirect.test.ts",
        "test/relay-attribution.test.ts",
        "test/relay-client.test.ts",
        "test/relay-signing.test.ts",
        "test/target.test.ts",
        "test/smoke.test.ts",
        "test/support/relay-stub.ts",
        "test/support/signed-block.ts",
    ),
    "toolchain (divergence makes a green run on one side prove less)": (
        "tsconfig.json",
        "vitest.config.ts",
        ".gitignore",
        "scripts/conformance.ts",
    ),
}

# Shared paths that legitimately differ, each with the reason. The gate asserts
# these still differ: one that has become identical is a stale exemption.
INTENTIONALLY_DIVERGENT: dict[str, str] = {
    "src/index.ts": "each ingress documents and wires its own request shaping",
    "test/pipeline.test.ts": (
        "same shared pipeline, but each package asserts its own contract: "
        "codex-ingress covers a failed identity projection, claude-ingress covers "
        "leaving the caller's identity alone"
    ),
    "test/worker.integration.test.ts": "asserts the ingress behaviour of its own package",
    "README.md": "documents the behaviour of its own Worker",
    "wrangler.toml": "separate deployment: own name, routes and bindings",
    ".env.example": "per-package local configuration",
    "package.json": "same dependencies, different package name",
    "package-lock.json": "lockfile of the above; identical tree, different root name",
}

# Protocol fixtures are deliberately absent from both maps: `conformance.py`
# already gates each one against the canonical copy in `protocol/`, which is a
# stronger check than mutual identity between the two packages.
#
# Derived from the canonical files rather than listed, so adding a protocol
# generation does not require editing this manifest -- but derived from
# `protocol/`, not from a filename pattern, so the exemption only exists while
# the canonical copy that justifies it exists. A fixture dropped into a package
# with no counterpart in `protocol/` is gated by nothing and still fails here.
def _gated_elsewhere() -> frozenset[str]:
    canonical = (ROOT / "protocol").glob("relay-protocol-v*.json")
    return frozenset(f"test/fixtures/{path.name}" for path in canonical)


GATED_ELSEWHERE = _gated_elsewhere()

# Files only one package may carry, with the reason it must not be shared.
PACKAGE_LOCAL: dict[str, dict[str, str]] = {
    "codex-ingress": {
        "src/config.ts": "Codex-only ingress configuration",
        "src/identity.ts": "projects an identity the Claude ingress must not",
        "test/identity.test.ts": "covers the above",
        "test/open-ingress.test.ts": "Codex ingress admission",
        "test/relay-egress.test.ts": "Codex egress",
    },
    "claude-ingress": {
        "src/cloak/attribution.ts": "Claude Code billing attribution",
        "src/cloak/beta.ts": "anthropic-beta assembly",
        "src/cloak/body.ts": "Claude request body shaping",
        "src/cloak/endpoint.ts": "Claude endpoint classification",
        "src/cloak/headers.ts": "Claude client header rebuild",
        "src/cloak/identity.ts": "Claude device/session derivation",
        "src/cloak/index.ts": "cloak composition order",
        "src/cloak/profile.ts": "pinned Claude Code profile",
        "test/cloak.test.ts": "covers the cloak",
        "test/ingress.test.ts": "Claude ingress",
    },
}


def authored_files(package: str) -> dict[str, pathlib.Path]:
    """Every authored file in a package, keyed by its package-relative path."""
    base = ROOT / package
    found: dict[str, pathlib.Path] = {}
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(base)
        if SKIP_DIRS.intersection(relative.parts):
            continue
        found[relative.as_posix()] = path
    return found


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_identical(
    trees: dict[str, dict[str, pathlib.Path]], verbose: bool
) -> tuple[int, int]:
    """Require each SHARED_IDENTICAL path to exist in both packages and match."""
    failures = 0
    checked = 0
    for reason, paths in SHARED_IDENTICAL.items():
        if verbose:
            print(f"  {reason}")
        for relative in paths:
            checked += 1
            missing = [pkg for pkg in PACKAGES if relative not in trees[pkg]]
            if missing:
                print(f"FAIL {relative}: missing from {', '.join(missing)}")
                failures += 1
                continue
            digests = {pkg: digest(trees[pkg][relative]) for pkg in PACKAGES}
            if len(set(digests.values())) == 1:
                if verbose:
                    print(f"    ok   {relative}  sha256={digests[PACKAGES[0]][:12]}")
                continue
            print(f"FAIL {relative}: drifted between packages")
            for pkg in PACKAGES:
                print(f"       {pkg:<14} sha256={digests[pkg]}")
            print(f"       diff: diff {PACKAGES[0]}/{relative} {PACKAGES[1]}/{relative}")
            failures += 1
    return failures, checked


def check_divergent(trees: dict[str, dict[str, pathlib.Path]], verbose: bool) -> int:
    """Report exemptions that have become identical, i.e. are now stale."""
    failures = 0
    if verbose:
        print("  exempted as divergent (checked for stale exemptions)")
    for relative, reason in INTENTIONALLY_DIVERGENT.items():
        if any(relative not in trees[pkg] for pkg in PACKAGES):
            continue  # only one side has it; not an identity question
        digests = {digest(trees[pkg][relative]) for pkg in PACKAGES}
        if len(digests) == 1:
            print(
                f"FAIL {relative}: exempted as divergent ({reason}) but the two "
                "copies are now byte-identical -- move it to SHARED_IDENTICAL "
                "or drop the exemption"
            )
            failures += 1
        elif verbose:
            print(f"    ok   {relative}  differs as expected ({reason})")
    return failures


def check_classified(trees: dict[str, dict[str, pathlib.Path]]) -> int:
    """Every authored file must fall into exactly one known category."""
    failures = 0
    known_shared = {p for paths in SHARED_IDENTICAL.values() for p in paths}
    overlap = known_shared & set(INTENTIONALLY_DIVERGENT)
    if overlap:
        print(f"FAIL manifest: {sorted(overlap)} listed as both identical and divergent")
        failures += 1

    for pkg in PACKAGES:
        local = set(PACKAGE_LOCAL[pkg])
        other = PACKAGES[1] if pkg == PACKAGES[0] else PACKAGES[0]
        for relative in sorted(trees[pkg]):
            if relative in known_shared or relative in INTENTIONALLY_DIVERGENT:
                continue
            if relative in GATED_ELSEWHERE or relative in local:
                continue
            where = "shared with" if relative in trees[other] else "absent from"
            print(
                f"FAIL {pkg}/{relative}: unclassified ({where} {other}). Add it to "
                "SHARED_IDENTICAL, INTENTIONALLY_DIVERGENT, or "
                f"PACKAGE_LOCAL['{pkg}'] in protocol/shared_drift.py"
            )
            failures += 1

        for relative in sorted(local):
            if relative in trees[pkg]:
                continue
            print(f"FAIL {pkg}/{relative}: listed as package-local but missing")
            failures += 1
        for relative in sorted(local & set(trees[other])):
            print(
                f"FAIL {relative}: listed as local to {pkg} but {other} carries it too"
            )
            failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="list every file checked, not just failures",
    )
    args = parser.parse_args()

    for pkg in PACKAGES:
        if not (ROOT / pkg).is_dir():
            print(f"FAIL: package missing at {ROOT / pkg}")
            return 1

    trees = {pkg: authored_files(pkg) for pkg in PACKAGES}

    identical_failures, checked = check_identical(trees, args.verbose)
    divergent_failures = check_divergent(trees, args.verbose)
    classified_failures = check_classified(trees)
    failures = identical_failures + divergent_failures + classified_failures

    lines = sum(
        len(trees[PACKAGES[0]][p].read_bytes().splitlines())
        for paths in SHARED_IDENTICAL.values()
        for p in paths
        if p in trees[PACKAGES[0]]
    )
    if failures:
        print(f"RESULT: {failures} shared-code check(s) failed")
        return 1
    print(
        f"RESULT: {checked} shared files byte-identical across "
        f"{' and '.join(PACKAGES)} ({lines} lines)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
