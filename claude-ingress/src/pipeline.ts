/**
 * The shared client-to-relay pipeline.
 *
 * Every ingress Worker in this repository performs the same ordered sequence:
 * resolve the target, resolve relay config, read a bounded body, optionally
 * project the request's identity, send the signed envelope through the relay,
 * then rewrite any redirect so the client cannot leave the relay path.
 *
 * That order is load-bearing rather than incidental:
 *
 *  - target and relay config resolve *before* the body is read, so a malformed
 *    request or a missing relay secret costs no memory;
 *  - relay config resolving early is what makes the relay mandatory. The whole
 *    point is that upstream traffic leaves the VPS address, so an absent or
 *    malformed configuration must fail the request rather than quietly fall
 *    back to the Worker's own Cloudflare egress;
 *  - redirect rewriting sits outside the relay try/catch so a rewrite failure
 *    is never misreported as a relay failure.
 *
 * It lives here as one owner because the alternative -- a copy per ingress --
 * means every future upstream re-derives the fail-closed ordering by hand, and
 * a copy that drifts on any of the points above is a security regression, not a
 * cosmetic one. What differs between ingresses is narrow and passed in: the body
 * ceiling variable, and whether the caller's identity is rewritten or forwarded
 * untouched.
 */
import { errorResponse } from "./errors";
import { RedirectError, rewriteLocation } from "./redirect";
import { RelayConfigError, readRelayConfig, type RelayEnv } from "./relay/config";
import { sendViaRelay } from "./relay/client";
import { parseTarget, TargetError, type TargetEnv } from "./target";

/**
 * The environment every ingress needs: relay egress plus target policy.
 *
 * An ingress adds its own body-ceiling variable and, for Codex, the identity
 * configuration, so this is an lower bound rather than the whole surface.
 */
export type PipelineEnv = RelayEnv & TargetEnv;

/**
 * What actually goes upstream, after an ingress has had its say.
 */
export interface ProjectedRequest {
  readonly headers: Headers;
  readonly body: Uint8Array;
}

export interface RelayHandlerSpec<E extends PipelineEnv> {
  /**
   * Reads the ingress's own body-ceiling variable.
   *
   * Passed as an accessor rather than a variable name so the name stays a
   * compile-time property of the ingress's `Env`; a string would push a typo to
   * runtime, where it would silently restore the default ceiling.
   */
  readonly maxBodyBytes: (env: E) => string | undefined;

  /**
   * Rewrites the caller's identity before egress.
   *
   * Omitted means "forward the client's own headers and body untouched", which
   * is correct when the real client already is what the upstream expects. A
   * thrown error is reported as an upstream failure, never as a client error:
   * failing to synthesize identity is this Worker's bug, not the caller's.
   *
   * May be async: deriving a stable identity requires WebCrypto digests, which
   * are promise-based. A synchronous implementation remains valid, so the
   * awaited union costs the purely-synchronous ingress nothing.
   */
  readonly projectRequest?: (
    request: Request,
    body: Uint8Array,
    env: E,
  ) => ProjectedRequest | Promise<ProjectedRequest>;
}

/**
 * Digit-only parse, so a malformed value falls back instead of yielding NaN and
 * silently disabling the ceiling.
 */
function positiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || !/^\d+$/.test(raw)) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

/**
 * Bounds Worker memory, not request shape. Long conversations plus file context
 * are legitimate; a body larger than this is not worth buffering to find out.
 */
const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

/**
 * The handler shape an ingress exports.
 *
 * Spelled out rather than returning `ExportedHandler<E>` because that type marks
 * `fetch` optional and widens the request's `cf` properties, which would push
 * both the presence check and the incoming-request typing onto every caller and
 * test.
 */
export interface RelayHandler<E extends PipelineEnv> {
  fetch(request: Request, env: E, ctx: ExecutionContext): Promise<Response>;
}

export function createRelayHandler<E extends PipelineEnv>(
  spec: RelayHandlerSpec<E>,
): RelayHandler<E> {
  return {
    async fetch(request: Request, env: E, _ctx: ExecutionContext): Promise<Response> {
      // There is no ingress gate: these Workers are open endpoints by design, so
      // a client that points its base URL here works with no custom headers and
      // no Worker-specific credential. Upstream authorization stays the caller's
      // own header, forwarded untouched.
      //
      // Client-supplied relay control headers are still stripped before egress,
      // in both the current `x-egress-relay-*` and the legacy `x-codex-relay-*`
      // namespace (see headers.ts): being open to callers must not let a caller
      // forge the Worker->relay envelope or its result attribution.
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

      if (body.byteLength > positiveInt(spec.maxBodyBytes(env), DEFAULT_MAX_BODY_BYTES)) {
        return errorResponse(413, "request body too large", "request_too_large");
      }

      let projected: ProjectedRequest;
      if (spec.projectRequest === undefined) {
        projected = { headers: request.headers, body };
      } else {
        try {
          projected = await spec.projectRequest(request, body, env);
        } catch {
          return errorResponse(502, "upstream request failed", "upstream_error");
        }
      }

      let response: Response;
      try {
        response = await sendViaRelay({
          relayUrl: relay.url,
          keyId: relay.keyId,
          secret: relay.secret,
          target,
          method: request.method,
          headers: projected.headers,
          body: projected.body,
        });
      } catch {
        // Generic message only: relay failures quote relay hostnames and signing
        // detail that must not reach the client.
        return errorResponse(502, "relay egress failed", "relay_unavailable");
      }

      // The relay never follows redirects, so a 3xx `Location` still points at
      // the upstream host. Left alone, a redirect-following client would connect
      // there directly from its own IP and bypass the fixed VPS egress entirely.
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
}
