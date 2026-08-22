/**
 * Test support: read the canonical header block back out of a relay envelope.
 *
 * The block is what the Worker actually signed and what the relay will replay
 * upstream, so assertions about "which headers reached the upstream" have to be
 * made against it rather than against the envelope's own headers.
 */
import { base64UrlDecode } from "../../src/relay/protocol";

export function signedHeaders(request: Request): Map<string, string> {
  const raw = request.headers.get("x-codex-relay-headers") ?? "";
  const block = new TextDecoder().decode(base64UrlDecode(raw));
  const parsed = new Map<string, string>();
  for (const line of block.split("\n")) {
    if (line.length === 0) continue;
    const separator = line.indexOf(":");
    parsed.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return parsed;
}

/** The upstream URL the relay was told to call, decoded from the envelope. */
export function signedTarget(request: Request): string {
  return new TextDecoder().decode(
    base64UrlDecode(request.headers.get("x-codex-relay-target") ?? ""),
  );
}
