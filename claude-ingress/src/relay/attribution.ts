import { errorResponse, type RelayErrorType } from "../errors";
import { readRelayResponseAttribution } from "./control";
import { logRelayAttributionFailure } from "./observability";

type ClientRelayError = readonly [
  status: number,
  message: string,
  type: RelayErrorType,
];

/**
 * How a relay-generated failure is presented to the client.
 *
 * Known machine codes preserve the failure class for caller policy and operator
 * diagnosis; none makes the current attempt recoverable, and this layer never
 * retries it. Internal gates (signature, nonce, protocol, body limit, config)
 * still collapse to one opaque `502 relay_unavailable`, because naming the gate
 * would tell a caller exactly which check it tripped.
 */
const RELAY_ERROR_MAP: ReadonlyMap<string, ClientRelayError> = new Map([
  ["relay_upstream_timeout", [504, "upstream request timed out", "upstream_timeout"]],
  ["relay_upstream_error", [502, "upstream request failed", "upstream_error"]],
  ["relay_forward_unavailable", [502, "upstream request failed", "upstream_error"]],
  ["relay_busy", [503, "relay is at capacity", "relay_busy"]],
]);

const RELAY_UNAVAILABLE: ClientRelayError = [
  502,
  "relay egress is unavailable",
  "relay_unavailable",
];

/**
 * Turn a relay reply into the response the client should see.
 *
 * The status code alone cannot answer "whose error is this": the relay's own 401
 * is indistinguishable from an upstream rejecting a bad API key, and an upstream
 * 502 is indistinguishable from a relay that could not connect. The parsed
 * attribution value is the single owner of that decision and of the metadata
 * emitted when the decision fails closed. The response is terminal in every
 * branch: attribution changes its classification and presentation, not whether
 * the current attempt can still complete.
 */
export function attributeRelayResponse(
  upstream: Response,
  projectHeaders: (headers: Headers) => Headers,
): Response {
  const attribution = readRelayResponseAttribution(upstream.headers);

  // Missing attribution means an unknown or pre-upgrade relay. Reading that as
  // `upstream` would pass a relay 401 straight through -- the exact leak the
  // header exists to prevent -- so absence fails closed to "relay error".
  if (attribution.result === "upstream") {
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: projectHeaders(upstream.headers),
    });
  }

  logRelayAttributionFailure(upstream.status, attribution);
  const [status, message, type] =
    RELAY_ERROR_MAP.get(attribution.error ?? "") ?? RELAY_UNAVAILABLE;

  // Built from scratch, never from the relay's body: the relay's own JSON names
  // the internal gate that rejected the request.
  return errorResponse(status, message, type);
}
