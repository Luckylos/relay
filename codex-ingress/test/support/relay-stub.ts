/**
 * Test support: make a stubbed relay reply look like a real one.
 *
 * The production relay stamps attribution headers (spec section 8) on every
 * response, and the Worker fails closed when they are absent -- an unattributed
 * reply could be a relay error masquerading as an upstream success. A stub that
 * omits them is therefore not a valid relay, and tests using one would be
 * asserting against a relay that cannot exist.
 */
const RESULT_HEADER = "x-codex-relay-result";
const REQUEST_ID_HEADER = "x-codex-relay-request-id";

/** Stamp a stubbed response as a genuine upstream reply relayed verbatim. */
export function asUpstream(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set(RESULT_HEADER, "upstream");
  headers.set(REQUEST_ID_HEADER, "test-request-id");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
