import type { RelayResponseAttribution } from "./control";

interface RelayAttributionFailureEvent {
  readonly event: "relay_attribution_failure";
  readonly relay_status: number;
  readonly relay_result: string | null;
  readonly relay_error: string | null;
  readonly relay_request_id: string | null;
  readonly cf_ray: string | null;
}

/**
 * Emit the operator-only diagnosis for a response that cannot be attributed to
 * the upstream.
 *
 * This event is diagnostic only: it neither marks the request retryable nor
 * attempts to recover a response that has already ended the current attempt.
 *
 * This boundary intentionally accepts only status plus parsed control metadata.
 * A Response, target, request headers and body cannot reach it, so credentials
 * and prompts cannot be added to the event by accidental object spreading.
 */
export function logRelayAttributionFailure(
  status: number,
  attribution: RelayResponseAttribution,
): void {
  const event: RelayAttributionFailureEvent = {
    event: "relay_attribution_failure",
    relay_status: status,
    relay_result: attribution.result,
    relay_error: attribution.error,
    relay_request_id: attribution.requestId,
    cf_ray: attribution.cfRay,
  };
  console.error(JSON.stringify(event));
}
