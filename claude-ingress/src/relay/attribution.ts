import { errorResponse, type RelayErrorType } from "../errors";

/**
 * Relay response control headers (spec section 8).
 *
 * These are an internal Worker<->relay channel and are consumed here: they must
 * never continue to the client.
 *
 * Read in both generations. The relay and this Worker deploy independently, so
 * a relay that has not yet been upgraded answers only in the legacy namespace
 * while an upgraded one answers in both. Reading only the current namespace
 * would see no `result` header at all and fail every request closed to
 * `502 relay_unavailable` -- a total outage produced by a rename, not by a
 * fault. Current is preferred so an upgraded relay's own value wins if an
 * upstream ever manages to place a legacy-named header.
 */
const RESULT_HEADERS = ["x-egress-relay-result", "x-codex-relay-result"] as const;
const ERROR_HEADERS = ["x-egress-relay-error", "x-codex-relay-error"] as const;
const REQUEST_ID_HEADERS = [
  "x-egress-relay-request-id",
  "x-codex-relay-request-id",
] as const;

function readControl(
  headers: Headers,
  names: readonly string[],
): string | null {
  for (const name of names) {
    const value = headers.get(name);
    if (value !== null) {
      return value.trim().toLowerCase();
    }
  }
  return null;
}

function readMetadata(headers: Headers, names: readonly string[]): string | null {
  for (const name of names) {
    const value = headers.get(name)?.trim();
    if (value) {
      return value;
    }
  }
  return null;
}

/**
 * How a relay-generated failure is presented to the client.
 *
 * Only three of the relay's machine codes describe something the client can act
 * on -- an upstream that timed out, an upstream that failed, and a relay at
 * capacity. Everything else names an internal gate (signature, nonce, protocol,
 * body limit, config), and naming it would tell a caller exactly which check it
 * tripped, so those all collapse to one opaque `502 relay_unavailable`.
 */
const RELAY_ERROR_MAP: ReadonlyMap<string, readonly [number, string, RelayErrorType]> = new Map([
  ["relay_upstream_timeout", [504, "upstream request timed out", "upstream_timeout"] as const],
  ["relay_upstream_error", [502, "upstream request failed", "upstream_error"] as const],
  ["relay_forward_unavailable", [502, "upstream request failed", "upstream_error"] as const],
  ["relay_busy", [503, "relay is at capacity", "relay_busy"] as const],
]);

const RELAY_UNAVAILABLE: readonly [number, string, RelayErrorType] = [
  502,
  "relay egress is unavailable",
  "relay_unavailable",
];

/**
 * Turn a relay reply into the response the client should see.
 *
 * The status code alone cannot answer "whose error is this": the relay's own 401
 * is indistinguishable from an upstream rejecting a bad API key, and an upstream
 * 502 is indistinguishable from a relay that could not connect. `Result` settles
 * it, so this is the single point where that decision is made.
 */
export function attributeRelayResponse(
  upstream: Response,
  projectHeaders: (headers: Headers) => Headers,
): Response {
  const result = readControl(upstream.headers, RESULT_HEADERS);

  // Missing attribution means an unknown or pre-upgrade relay. Reading that as
  // `upstream` would pass a relay 401 straight through -- the exact leak the
  // header exists to prevent -- so absence fails closed to "relay error".
  if (result === "upstream") {
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: projectHeaders(upstream.headers),
    });
  }

  const machineCode = readControl(upstream.headers, ERROR_HEADERS);

  // The client must not learn which internal gate rejected the request, but the
  // operator must be able to distinguish that gate from a headerless Cloudflare
  // or tunnel response. Keep the event deliberately metadata-only: no target,
  // request headers, response headers, or body can carry credentials or prompts
  // into Worker logs.
  console.error(
    JSON.stringify({
      event: "relay_attribution_failure",
      relay_status: upstream.status,
      relay_result: result,
      relay_error: machineCode,
      relay_request_id: readMetadata(upstream.headers, REQUEST_ID_HEADERS),
      cf_ray: readMetadata(upstream.headers, ["cf-ray"]),
    }),
  );

  const [status, message, type] = RELAY_ERROR_MAP.get(machineCode ?? "") ?? RELAY_UNAVAILABLE;

  // Built from scratch, never from the relay's body: the relay's own JSON names
  // the internal gate that rejected the request.
  return errorResponse(status, message, type);
}
