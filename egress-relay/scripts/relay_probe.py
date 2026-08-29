#!/usr/bin/env python3
"""Sign a relay-protocol request and POST it to a running relay.

Mirrors src/relay/{protocol,signing}.ts and relay_protocol.rs so a real signed
request can be driven without the Worker. Run --selftest first: it reproduces the
shared fixtures so a probe bug cannot be misread as a relay failure.

Signs v2 by default. `--v1` still signs the previous generation, which is how an
operator confirms a relay's dual-read window actually accepts both rather than
only the generation it was last redeployed with.
"""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sys
import time
import urllib.error
import urllib.request

# This subtree's own fixtures, so the probe works when egress-relay/ is used
# standalone. protocol/conformance.py enforces byte-identity with the Workers'
# copies and with the canonical protocol/ copies.
FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "tests/fixtures"

# Signing-domain separator, one per generation.
#
# v1 keeps its original token forever: it is the domain a relay that has not been
# redeployed still verifies against, so renaming it in place would invalidate
# every signature already in flight.
DOMAIN_SEPARATORS = {
    1: "codex-relay-v1",
    2: "egress-relay-v2",
}

# Control-header namespace per generation. The rename is what v2 is for, so the
# probe must send the names matching whatever domain it signed under -- sending
# v2's signature under v1's header names would be rejected as a bad signature
# and read as a relay fault rather than a probe bug.
CONTROL_PREFIXES = {
    1: "x-codex-relay-",
    2: "x-egress-relay-",
}

CURRENT_VERSION = 2


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def normalize_header_value(value):
    """Spec §5.2: collapse runs of SPACE/TAB only and strip the ends.

    `" ".join(value.split())` would also collapse NBSP, form feed and every
    other Unicode space, disagreeing with relay_protocol.rs and protocol.ts.
    """
    out = []
    pending = False
    for character in value:
        if character in " \t":
            if out:
                pending = True
            continue
        if pending:
            out.append(" ")
            pending = False
        out.append(character)
    return "".join(out)


def canonical_headers(headers):
    lines = []
    for name, value in sorted(
        (n.lower(), normalize_header_value(v)) for n, v in headers
    ):
        lines.append(f"{name}:{value}\n")
    return "".join(lines)


def canonical_request(
    key_id, timestamp, nonce, method, target, digest, block, version=CURRENT_VERSION
):
    """Field order/encoding frozen by the protocol/ fixtures: the generation's
    domain separator, then base64url target and header block.

    Only line 1 varies by generation. An unknown version raises rather than
    defaulting, so a future v3 cannot be silently signed under v2's domain.
    """
    if version not in DOMAIN_SEPARATORS:
        raise SystemExit(f"unsupported relay protocol version: {version}")
    return "\n".join([
        DOMAIN_SEPARATORS[version],
        key_id,
        str(timestamp),
        nonce,
        method.upper(),
        b64u(target.encode()),
        digest,
        b64u(block.encode()),
    ])


def selftest():
    """Reproduce every generation's fixture.

    Both are checked, not just the one the probe sends by default: the probe is
    the operator's tool for confirming a relay still accepts v1 during the
    dual-read window, so a v1 regression here would break exactly the check the
    window depends on.
    """
    for version in sorted(DOMAIN_SEPARATORS):
        path = FIXTURES / f"relay-protocol-v{version}.json"
        f = json.loads(path.read_text())
        assert f["version"] == version, f"{path.name}: version field mismatch"
        block = canonical_headers([(n, v) for n, v in f["headers"]])
        assert block == f["canonical_header_block"], f"v{version} header block mismatch"
        digest = b64u(hashlib.sha256(f["body_utf8"].encode()).digest())
        assert digest == f["body_sha256"], f"v{version} digest mismatch"
        canonical = canonical_request(
            f["key_id"],
            f["timestamp"],
            f["nonce"],
            f["method"],
            f["target"],
            digest,
            block,
            version=version,
        )
        assert canonical == f["canonical_request"], f"v{version} canonical mismatch"
        signature = b64u(
            hmac.new(f["secret"].encode(), canonical.encode(), hashlib.sha256).digest()
        )
        assert signature == f["signature"], f"v{version} signature mismatch"
        print(f"probe selftest OK v{version}: canonical + signature match the fixture")


def build(
    relay, target, method, body, key_id, secret, extra_headers=(),
    version=CURRENT_VERSION,
):
    headers = [("accept", "application/json"), *extra_headers]
    timestamp = int(time.time())
    nonce = b64u(secrets.token_bytes(16))
    block = canonical_headers(headers)
    digest = b64u(hashlib.sha256(body).digest())
    canonical = canonical_request(
        key_id, timestamp, nonce, method, target, digest, block, version=version
    )
    signature = b64u(hmac.new(secret, canonical.encode(), hashlib.sha256).digest())
    # The namespace must match the domain just signed under: a relay resolves the
    # generation from the header names, so a mismatch reads as a bad signature
    # and would be misdiagnosed as a relay fault.
    prefix = CONTROL_PREFIXES[version]
    return urllib.request.Request(
        relay,
        data=body,
        method="POST",
        headers={
            "content-type": "application/octet-stream",
            # Cloudflare's edge answers the default Python-urllib UA with
            # error 1010 before the request ever reaches the relay, so a probe
            # must not advertise it. The real Worker uses fetch() and is
            # unaffected.
            "user-agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"
            ),
            f"{prefix}version": str(version),
            f"{prefix}key-id": key_id,
            f"{prefix}timestamp": str(timestamp),
            f"{prefix}nonce": nonce,
            f"{prefix}method": method.upper(),
            f"{prefix}target": b64u(target.encode()),
            f"{prefix}body-sha256": digest,
            f"{prefix}headers": b64u(block.encode()),
            f"{prefix}signature": signature,
        },
    )


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--selftest":
        selftest()
        return

    # Consumed before the positionals so the existing
    # `relay_probe.py RELAY TARGET [METHOD] [BODY]` call shape is unchanged.
    version = CURRENT_VERSION
    if argv and argv[0] == "--v1":
        version = 1
        argv = argv[1:]

    relay, target = argv[0], argv[1]
    method = argv[2] if len(argv) > 2 else "GET"
    body = (argv[3] if len(argv) > 3 else "").encode()

    request = build(
        relay, target, method, body,
        os.environ["KEY_ID"], os.environ["SECRET"].encode(),
        version=version,
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(f"[{response.status}]")
            print(response.read().decode("utf-8", "replace")[:700])
    except urllib.error.HTTPError as error:
        print(f"[{error.code}]")
        print(error.read().decode("utf-8", "replace")[:700])


if __name__ == "__main__":
    main()
