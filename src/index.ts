import { readIdentityConfig, type IdentityEnv, type IdentityConfig } from "./config";
import { errorResponse } from "./errors";
import { projectIdentity, resolveIdentity } from "./identity";
import { authenticateIngress, type IngressEnv } from "./ingress-auth";
import { RelayConfigError, readRelayConfig, type RelayEnv } from "./relay/config";
import { sendViaRelay } from "./relay/client";
import { parseTarget, TargetError } from "./target";

export interface Env extends IdentityEnv, RelayEnv, IngressEnv {
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
    // First gate, before target parsing, body reads or any egress: an
    // unauthenticated caller must not be able to probe target validity, consume
    // relay quota or learn anything about relay configuration.
    const auth = authenticateIngress(request.headers, env);
    if (auth.outcome === "misconfigured") {
      return errorResponse(
        502,
        "ingress authentication is not configured",
        "ingress_misconfigured",
      );
    }
    if (auth.outcome === "unauthorized") {
      // Generic body: it must not reveal whether a token was presented.
      return errorResponse(401, "unauthorized", "unauthorized");
    }

    let target;
    try {
      target = parseTarget(request);
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

    try {
      return await sendViaRelay({
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
  },
};

export default worker satisfies ExportedHandler<Env>;
