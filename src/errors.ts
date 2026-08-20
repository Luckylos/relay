export type RelayErrorType =
  | "invalid_target"
  | "request_too_large"
  | "upstream_error"
  | "relay_unavailable"
  | "unauthorized"
  | "ingress_misconfigured"
  | "invalid_upstream_redirect"
  | "proxy_unavailable"
  | "proxy_timeout";

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
