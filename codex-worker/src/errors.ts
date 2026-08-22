export type RelayErrorType =
  | "invalid_target"
  | "request_too_large"
  | "upstream_error"
  | "upstream_timeout"
  | "relay_unavailable"
  | "relay_busy"
  | "invalid_upstream_redirect";

export function errorResponse(
  status: number,
  message: string,
  type: RelayErrorType,
): Response {
  return new Response(JSON.stringify({ error: { message, type } }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
