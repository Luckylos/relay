/**
 * Claude Code application-layer cloak.
 *
 * Composes the four concerns into one `projectRequest` hook: profile, identity,
 * body shape, headers. The order below is the only one that is correct.
 *
 *   1. classify the endpoint      -- decides which beta profile applies
 *   2. derive identity            -- needed by the body's metadata block
 *   3. transform the body         -- reports what the request actually asks for
 *   4. build the beta header      -- from the *transformed* body, never the caller's
 *   5. rebuild the headers        -- delete-then-write over the survivors
 *
 * Step 4 depending on step 3 is the point. Deriving betas from the incoming
 * header would let a caller's guess drive what this Worker claims; deriving them
 * from the body it is about to send means a beta is announced only when the field
 * it describes is present.
 *
 * Scope, stated plainly: this is application-layer only. The relay reaches
 * upstream with rustls over HTTP/2, so the TLS ClientHello, the HTTP/2 settings
 * and the resulting JA4 are the relay's, not a real client's. No amount of header
 * work changes that, and this module does not pretend otherwise. Billing
 * attribution (CCH and its signed headers) is likewise out of scope by decision,
 * so requests are shaped like Claude Code without claiming its billing identity.
 */
import type { ProjectedRequest } from "../pipeline";
import { buildBetaHeader } from "./beta";
import { transformBody } from "./body";
import { classifyEndpoint } from "./endpoint";
import { buildCloakHeaders } from "./headers";
import { deriveIdentity } from "./identity";
import { readCloakProfile, type CloakProfileEnv } from "./profile";

export type CloakEnv = CloakProfileEnv;

export interface CloakDependencies {
  /** Injected so tests pin the date rather than racing midnight. */
  readonly today: () => string;
}

const runtimeDependencies: CloakDependencies = {
  today: () => new Date().toISOString().slice(0, 10),
};

/**
 * Shape one request into Claude Code form.
 *
 * Always applied, with no caller-detection branch. Trusting a caller's claim to
 * be real Claude Code would mean the presented identity depends on a signal the
 * caller controls, and forwarding one caller's device and session identity while
 * synthesizing another's puts two machines behind a single credential. Rebuilding
 * unconditionally is both simpler and more consistent.
 */
export async function projectClaudeRequest(
  request: Request,
  body: Uint8Array,
  env: CloakEnv,
  dependencies: CloakDependencies = runtimeDependencies,
): Promise<ProjectedRequest> {
  const profile = readCloakProfile(env);
  const endpoint = classifyEndpoint(new URL(request.url).pathname);
  const identity = await deriveIdentity(request.headers.get("x-api-key"), profile);

  const transformed = transformBody(body, {
    endpoint,
    identity,
    contentType: request.headers.get("content-type"),
    today: dependencies.today(),
  });

  const betaHeader = buildBetaHeader(
    request.headers.get("anthropic-beta"),
    transformed.capabilities,
    endpoint,
  );

  return {
    headers: buildCloakHeaders(request.headers, profile, betaHeader),
    body: transformed.body,
  };
}
