import type { TargetRequest } from "../target";
import { isStrippedRequestHeader, projectResponseHeaders } from "../headers";
import { attributeRelayResponse } from "./attribution";
import { CURRENT_VERSION, base64UrlEncode, canonicalizeHeaders, utf8 } from "./protocol";
import { sha256Base64Url, signRelayRequest } from "./signing";

export type RelayFetch = (request: Request) => Promise<Response>;

export interface RelayRequest {
  relayUrl: string;
  keyId: string;
  secret: string;
  target: TargetRequest;
  method: string;
  headers: Headers;
  body: Uint8Array;
  fetchImpl?: RelayFetch;
  timestamp?: number;
  nonce?: string;
}

function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Business headers destined for the upstream, as name/value pairs.
 *
 * Hop-by-hop, relay control, source-revealing and ingress-auth headers are all
 * dropped by `isStrippedRequestHeader`, so a client can neither forge an envelope
 * field nor leak its own origin to the upstream.
 */
export function projectRelayHeaders(
  headers: Headers,
): Array<readonly [string, string]> {
  const projected: Array<readonly [string, string]> = [];
  for (const [rawName, value] of headers) {
    const name = rawName.toLowerCase();
    if (isStrippedRequestHeader(name)) {
      continue;
    }
    projected.push([name, value] as const);
  }
  return projected;
}

export async function sendViaRelay(request: RelayRequest): Promise<Response> {
  const target = request.target.url.toString();
  const method = request.method.toUpperCase();
  const headers = projectRelayHeaders(request.headers);
  const timestamp = request.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = request.nonce ?? newNonce();

  const signature = await signRelayRequest(
    {
      version: CURRENT_VERSION,
      keyId: request.keyId,
      timestamp,
      nonce,
      method,
      target,
      headers,
      body: request.body,
    },
    request.secret,
  );

  // The envelope names must belong to the same generation as the signing domain
  // the signature was produced under. A relay detects the generation from these
  // names and then verifies against that generation's domain, so a v2 signature
  // sent under legacy names verifies against the v1 domain and is rejected as a
  // bad signature -- an authentication failure whose real cause is a mismatched
  // rename. Both are derived from CURRENT_VERSION so they cannot drift apart.
  const envelope = new Headers({
    "content-type": "application/octet-stream",
    "x-egress-relay-version": String(CURRENT_VERSION),
    "x-egress-relay-key-id": request.keyId,
    "x-egress-relay-timestamp": String(timestamp),
    "x-egress-relay-nonce": nonce,
    "x-egress-relay-method": method,
    "x-egress-relay-target": base64UrlEncode(utf8(target)),
    "x-egress-relay-body-sha256": await sha256Base64Url(request.body),
    "x-egress-relay-headers": base64UrlEncode(utf8(canonicalizeHeaders(headers))),
    "x-egress-relay-signature": signature,
  });

  const send = request.fetchImpl ?? ((outbound: Request) => fetch(outbound));
  const upstream = await send(
    new Request(request.relayUrl, {
      method: "POST",
      headers: envelope,
      body: request.body.byteLength > 0 ? (request.body as unknown as BodyInit) : undefined,
    }),
  );

  // Whose error is this? The status code cannot say, so attribution is decided
  // from the relay's control headers before anything reaches the client.
  return attributeRelayResponse(upstream, projectResponseHeaders);
}
