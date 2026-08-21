#!/usr/bin/env python3
"""Sign a relay-protocol-v1 request and POST it to a running relay.

Mirrors src/relay/{protocol,signing}.ts and relay_protocol.rs so a real signed
request can be driven without the Worker. Run --selftest first: it reproduces the
shared fixture so a probe bug cannot be misread as a relay failure.
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

# This subtree's own fixture, so the probe works when relay-server/ is used
# standalone. protocol/conformance.py enforces byte-identity with the Worker's
# copy and with protocol/relay-protocol-v1.json.
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "tests/fixtures/relay-protocol-v1.json"


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


def canonical_request(key_id, timestamp, nonce, method, target, digest, block):
    """Field order/encoding frozen by protocol/relay-protocol-v1.json:
    literal version prefix, then base64url target and header block."""
    return "\n".join([
        "codex-relay-v1",
        key_id,
        str(timestamp),
        nonce,
        method.upper(),
        b64u(target.encode()),
        digest,
        b64u(block.encode()),
    ])


def selftest():
    f = json.loads(FIXTURE.read_text())
    block = canonical_headers([(n, v) for n, v in f["headers"]])
    assert block == f["canonical_header_block"], "header block mismatch"
    digest = b64u(hashlib.sha256(f["body_utf8"].encode()).digest())
    assert digest == f["body_sha256"], "digest mismatch"
    canonical = canonical_request(
        f["key_id"], f["timestamp"], f["nonce"], f["method"], f["target"], digest, block
    )
    assert canonical == f["canonical_request"], "canonical mismatch"
    signature = b64u(
        hmac.new(f["secret"].encode(), canonical.encode(), hashlib.sha256).digest()
    )
    assert signature == f["signature"], "signature mismatch"
    print("probe selftest OK: canonical + signature match the shared fixture")


def build(relay, target, method, body, key_id, secret, extra_headers=()):
    headers = [("accept", "application/json"), *extra_headers]
    timestamp = int(time.time())
    nonce = b64u(secrets.token_bytes(16))
    block = canonical_headers(headers)
    digest = b64u(hashlib.sha256(body).digest())
    canonical = canonical_request(
        key_id, timestamp, nonce, method, target, digest, block
    )
    signature = b64u(hmac.new(secret, canonical.encode(), hashlib.sha256).digest())
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
            "x-codex-relay-version": "1",
            "x-codex-relay-key-id": key_id,
            "x-codex-relay-timestamp": str(timestamp),
            "x-codex-relay-nonce": nonce,
            "x-codex-relay-method": method.upper(),
            "x-codex-relay-target": b64u(target.encode()),
            "x-codex-relay-body-sha256": digest,
            "x-codex-relay-headers": b64u(block.encode()),
            "x-codex-relay-signature": signature,
        },
    )


def main():
    if sys.argv[1] == "--selftest":
        selftest()
        return

    relay, target = sys.argv[1], sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"
    body = (sys.argv[4] if len(sys.argv) > 4 else "").encode()

    request = build(
        relay, target, method, body,
        os.environ["KEY_ID"], os.environ["SECRET"].encode(),
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
