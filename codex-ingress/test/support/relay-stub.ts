/**
 * Test support: make a stubbed relay reply look like a real one.
 *
 * The production relay stamps attribution headers (spec section 8) on every
 * response, and the Worker fails closed when they are absent -- an unattributed
 * reply could be a relay error masquerading as an upstream success. A stub that
 * omits them is therefore not a valid relay, and tests using one would be
 * asserting against a relay that cannot exist.
 *
 * An upgraded relay stamps both generations, because the two ingresses deploy
 * independently and it cannot know which one is calling. This stub mirrors that
 * so the default fixture is the relay that actually exists. Tests that need a
 * single-generation relay -- a pre-upgrade one answering only in the legacy
 * namespace -- build that case explicitly rather than changing this default.
 */
const RESULT_HEADERS = ["x-egress-relay-result", "x-codex-relay-result"] as const;
const REQUEST_ID_HEADERS = [
  "x-egress-relay-request-id",
  "x-codex-relay-request-id",
] as const;

/** Stamp a stubbed response as a genuine upstream reply relayed verbatim. */
export function asUpstream(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const name of RESULT_HEADERS) {
    headers.set(name, "upstream");
  }
  for (const name of REQUEST_ID_HEADERS) {
    headers.set(name, "test-request-id");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
