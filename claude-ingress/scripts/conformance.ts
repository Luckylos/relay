/**
 * Cross-language conformance runner for relay protocol v1.
 *
 * Reads the vector payload from stdin (see `protocol/conformance.py`) and emits
 * one JSON object mapping vector name -> {canonical, signature}. The Python
 * driver diffs this against the Rust relay's output; any disagreement in
 * canonical form or HMAC fails CI.
 *
 * Runs on plain Node (not workerd) so the gate stays cheap. `crypto.subtle` and
 * `btoa`/`atob` are globals in Node 22, matching the Worker runtime's API.
 */
import { buildCanonicalRequest } from "../src/relay/protocol";
import { sha256Base64Url, signRelayRequest } from "../src/relay/signing";

type Vector = {
  name: string;
  /**
   * Protocol generation this vector is signed under.
   *
   * Carried per vector rather than per payload so one run drives both
   * generations. A runner that ignored this field would agree with the others on
   * v1 and silently never exercise v2.
   */
  version: number;
  key_id: string;
  timestamp: number;
  method: string;
  target: string;
  headers: Array<[string, string]>;
  body_utf8: string;
};

type Payload = {
  secret: string;
  nonce: string;
  vectors: Vector[];
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

const payload = JSON.parse(await readStdin()) as Payload;
const results: Record<string, { canonical: string; signature: string }> = {};

for (const vector of payload.vectors) {
  const body = new TextEncoder().encode(vector.body_utf8);
  const input = {
    version: vector.version,
    keyId: vector.key_id,
    timestamp: vector.timestamp,
    nonce: payload.nonce,
    method: vector.method,
    target: vector.target,
    headers: vector.headers,
    body,
  };

  const bodySha256 = await sha256Base64Url(body);
  results[vector.name] = {
    canonical: buildCanonicalRequest(input, bodySha256),
    signature: await signRelayRequest(input, payload.secret),
  };
}

process.stdout.write(`${JSON.stringify(results)}\n`);
