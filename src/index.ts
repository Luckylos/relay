import { readIdentityConfig, type IdentityEnv, type IdentityConfig } from "./config";
import { errorResponse } from "./errors";
import { projectIdentity, resolveIdentity } from "./identity";
import { sendDirect } from "./egress/direct";
import { parseTarget, TargetError } from "./target";

export interface Env extends IdentityEnv {
  EGRESS_PROXY_URL?: string;
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

function maxBodyBytes(env: Env): number {
  const raw = env.CODEX_PROXY_MAX_BODY_BYTES;
  if (!raw || !/^\d+$/.test(raw)) {
    return DEFAULT_MAX_BODY_BYTES;
  }

  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : DEFAULT_MAX_BODY_BYTES;
}

const worker = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    let target;
    try {
      target = parseTarget(request);
    } catch (error) {
      if (error instanceof TargetError) {
        return errorResponse(400, "invalid target", "invalid_target");
      }
      return errorResponse(400, "invalid target", "invalid_target");
    }

    if (env.EGRESS_PROXY_URL?.length) {
      return errorResponse(
        502,
        "configured proxy egress is unavailable",
        "proxy_unavailable",
      );
    }

    let body: Uint8Array;
    try {
      body = new Uint8Array(await request.arrayBuffer());
    } catch {
      return errorResponse(400, "invalid request body", "upstream_error");
    }

    if (body.byteLength > maxBodyBytes(env)) {
      return errorResponse(413, "request body too large", "request_too_large");
    }

    try {
      const identity = resolveIdentity(request.headers, identityConfig(env));
      const headers = projectIdentity(identity, request.headers);
      const projectedBody = identity.ensureBodyMetadata(
        request.headers.get("content-type"),
        body,
      );

      return await sendDirect({
        target,
        method: request.method,
        headers,
        body: projectedBody,
      });
    } catch {
      return errorResponse(502, "upstream request failed", "upstream_error");
    }
  },
};

export default worker satisfies ExportedHandler<Env>;
