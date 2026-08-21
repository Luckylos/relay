import { readIdentityConfig, type IdentityEnv, type IdentityConfig } from "./config";
import { errorResponse } from "./errors";
import { projectIdentity, resolveIdentity } from "./identity";
import { RedirectError, rewriteLocation } from "./redirect";
import { RelayConfigError, readRelayConfig, type RelayEnv } from "./relay/config";
import { sendViaRelay } from "./relay/client";
import { parseTarget, TargetError, type TargetEnv } from "./target";

export interface Env extends IdentityEnv, RelayEnv, TargetEnv {
  CODEX_PROXY_MAX_BODY_BYTES?: string;
}

const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;
const configCache = new WeakMap<object, IdentityConfig>();

function identityConfig(env: Env): IdentityConfig {
  const existing = configCache.get(env);
  if (existing) {
    return existing;
  }

  const created = readIdentityConfig(env);
  configCache.set(env, created);
  return created;
}

function positiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || !/^\d+$/.test(raw)) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

const worker = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // There is no ingress gate: this Worker is an open endpoint by design, so any
    // client that points its base URL here works with no custom headers and no
    // Worker-specific credential. Upstream authorization stays the caller's own
    // `Authorization` header, which is forwarded untouched.
    //
    // Client-supplied `x-codex-relay-*` headers are still stripped before egress
    // (see headers.ts): being open to callers must not let a caller forge the
    // Worker->relay envelope.
    let target;
    try {
      target = parseTarget(request, env);
    } catch (error) {
      if (error instanceof TargetError) {
        return errorResponse(400, "invalid target", "invalid_target");
      }
      return errorResponse(400, "invalid target", "invalid_target");
    }

    // Resolved before the body is even read. The relay is the only egress: its
    // whole purpose is that upstream traffic leaves the VPS address, so a
    // missing or malformed relay configuration must fail the request rather than
    // quietly fall back to the Worker's own Cloudflare egress.
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

    if (body.byteLength > positiveInt(env.CODEX_PROXY_MAX_BODY_BYTES, DEFAULT_MAX_BODY_BYTES)) {
      return errorResponse(413, "request body too large", "request_too_large");
    }

    let projected;
    try {
      const identity = resolveIdentity(request.headers, identityConfig(env));
      const headers = projectIdentity(identity, request.headers);
      const projectedBody = identity.ensureBodyMetadata(
        request.headers.get("content-type"),
        body,
      );

      projected = { headers, body: projectedBody };
    } catch {
      return errorResponse(502, "upstream request failed", "upstream_error");
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
      // Generic message only: relay failures quote relay hostnames and
      // signing detail that must not reach the client.
      return errorResponse(502, "relay egress failed", "relay_unavailable");
    }

    // The relay never follows redirects, so a 3xx `Location` still points at the
    // upstream host. Left alone, a redirect-following client would connect there
    // directly from its own IP and bypass the fixed VPS egress entirely.
    //
    // Kept outside the block above so a rewrite failure is never misreported as a
    // relay failure, and the relay's own errors keep their own mapping.
    const location = response.headers.get("location");
    if (location === null) {
      return response;
    }

    let rewritten: string;
    try {
      rewritten = rewriteLocation(location, target, new URL(request.url), env);
    } catch (error) {
      if (error instanceof RedirectError) {
        // Fail closed: never hand the client a Location that would take it off the
        // relay path, and never leak the upstream's own Location value.
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
