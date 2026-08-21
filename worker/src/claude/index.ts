/**
 * Claude ingress.
 *
 * Same egress guarantees as the Codex Worker -- open to clients, mandatory
 * relay, bounded upstreams -- with one deliberate difference: the client's own
 * identity is forwarded untouched.
 *
 * The Codex Worker synthesizes identity (`user-agent`, `originator`, the
 * `x-codex-*` set, and a `client_metadata` field injected into the JSON body)
 * because its callers are not Codex and the upstream channel expects
 * Codex-shaped traffic. Here the real client *is* Claude Code, and it already
 * sends its own `user-agent`, `anthropic-version`, `anthropic-beta` and
 * `x-api-key`. Rewriting any of that would replace correct identity with a
 * guess, and injecting a body field would corrupt a request the client composed
 * itself. So this Worker removes only the headers that must not travel --
 * hop-by-hop, Cloudflare source-revealing, and the relay's own control prefix,
 * all handled by `projectRelayHeaders` -- and changes nothing else.
 *
 * Deliberately NOT shared with the Codex entrypoint: identity. Deliberately
 * shared: the relay envelope, signing, target parsing, redirect rewriting and
 * header stripping. The signing protocol has to stay byte-identical with the
 * Rust relay's conformance vectors, so a second copy of it would be a
 * correctness risk, not a convenience.
 */
import { errorResponse } from "../errors";
import { RedirectError, rewriteLocation } from "../redirect";
import { RelayConfigError, readRelayConfig, type RelayEnv } from "../relay/config";
import { sendViaRelay } from "../relay/client";
import { parseTarget, TargetError, type TargetEnv } from "../target";

export interface Env extends RelayEnv, TargetEnv {
  CLAUDE_PROXY_MAX_BODY_BYTES?: string;
}

/**
 * Claude Code sends long conversations plus file context, so the ceiling exists
 * to bound Worker memory, not to police request shape.
 */
const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

/**
 * Digit-only parse, so a malformed value falls back instead of yielding NaN and
 * silently disabling the ceiling.
 *
 * Duplicated from the Codex entrypoint on purpose: the two Workers are
 * independent deployments, and drift in a body ceiling is harmless, whereas
 * editing the live Codex Worker to dedupe six lines is not.
 */
function positiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || !/^\d+$/.test(raw)) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

const worker = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // No ingress gate, matching the Codex Worker: a client configured with
    // nothing but `ANTHROPIC_BASE_URL` and its own key must work. Upstream
    // authorization stays the caller's own `x-api-key` or `Authorization`
    // header, forwarded untouched.
    let target;
    try {
      target = parseTarget(request, env);
    } catch (error) {
      // Only a TargetError is the caller's fault. Anything else is a bug here,
      // and reporting it as `invalid_target` would blame the client for it, so
      // it propagates instead of being flattened into a 400.
      if (error instanceof TargetError) {
        return errorResponse(400, "invalid target", "invalid_target");
      }
      throw error;
    }

    // Resolved before the body is read. The relay is the only egress: its whole
    // purpose is that upstream traffic leaves the VPS address, so a missing or
    // malformed relay configuration must fail the request rather than quietly
    // fall back to the Worker's own Cloudflare egress.
    let relay;
    try {
      relay = readRelayConfig(env);
    } catch (error) {
      if (error instanceof RelayConfigError) {
        return errorResponse(502, "relay egress is unavailable", "relay_unavailable");
      }
      throw error;
    }

    let body: Uint8Array;
    try {
      body = new Uint8Array(await request.arrayBuffer());
    } catch {
      return errorResponse(400, "invalid request body", "upstream_error");
    }

    if (body.byteLength > positiveInt(env.CLAUDE_PROXY_MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES)) {
      return errorResponse(413, "request body too large", "request_too_large");
    }

    let response: Response;
    try {
      // `request.headers` goes in as-is. `sendViaRelay` strips what must not
      // travel; everything the client meant to send -- including the Anthropic
      // version and beta headers, which the API requires -- survives.
      response = await sendViaRelay({
        relayUrl: relay.url,
        keyId: relay.keyId,
        secret: relay.secret,
        target,
        method: request.method,
        headers: request.headers,
        body,
      });
    } catch {
      // Generic message only: relay failures quote relay hostnames and signing
      // detail that must not reach the client.
      return errorResponse(502, "relay egress failed", "relay_unavailable");
    }

    // The relay never follows redirects, so a 3xx `Location` still points at the
    // upstream host. Left alone, a redirect-following client would connect there
    // directly from its own IP and bypass the fixed VPS egress entirely.
    const location = response.headers.get("location");
    if (location === null) {
      return response;
    }

    let rewritten: string;
    try {
      rewritten = rewriteLocation(location, target, new URL(request.url), env);
    } catch (error) {
      if (error instanceof RedirectError) {
        // Fail closed: never hand the client a Location that would take it off
        // the relay path, and never leak the upstream's own Location value.
        return errorResponse(502, "invalid upstream redirect", "invalid_upstream_redirect");
      }
      throw error;
    }

    const headers = new Headers(response.headers);
    headers.set("location", rewritten);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};

export default worker satisfies ExportedHandler<Env>;
