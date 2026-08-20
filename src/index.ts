import { readIdentityConfig, type IdentityEnv, type IdentityConfig } from "./config";
import { errorResponse } from "./errors";
import { projectIdentity, resolveIdentity } from "./identity";
import { sendDirect } from "./egress/direct";
import {
  DEFAULT_TUNNEL_TIMEOUT_MS,
  ProxyConfigError,
  ProxyError,
  parseProxyUrl,
  sendViaProxy,
  type ProxyConfig,
} from "./egress/proxy";
import { parseTarget, TargetError } from "./target";

export interface Env extends IdentityEnv {
  /**
   * `socks5://[user:pass@]host:port` (or `socks5h://`). Unset means direct
   * Cloudflare egress. Carries credentials, so it belongs in a Worker secret.
   */
  EGRESS_PROXY_URL?: string;
  CODEX_PROXY_MAX_BODY_BYTES?: string;
  CODEX_PROXY_TUNNEL_TIMEOUT_MS?: string;
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
    let target;
    try {
      target = parseTarget(request);
    } catch (error) {
      if (error instanceof TargetError) {
        return errorResponse(400, "invalid target", "invalid_target");
      }
      return errorResponse(400, "invalid target", "invalid_target");
    }

    // Resolved before any egress so a misconfigured proxy fails closed instead
    // of quietly leaking the request out of the Worker's own IP.
    let proxy: ProxyConfig | undefined;
    if (env.EGRESS_PROXY_URL?.length) {
      try {
        proxy = parseProxyUrl(env.EGRESS_PROXY_URL);
      } catch (error) {
        if (error instanceof ProxyConfigError) {
          return errorResponse(
            502,
            "configured proxy egress is unavailable",
            "proxy_unavailable",
          );
        }
        throw error;
      }
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

    let egress;
    try {
      const identity = resolveIdentity(request.headers, identityConfig(env));
      const headers = projectIdentity(identity, request.headers);
      const projectedBody = identity.ensureBodyMetadata(
        request.headers.get("content-type"),
        body,
      );

      egress = {
        target,
        method: request.method,
        headers,
        body: projectedBody,
      };
    } catch {
      return errorResponse(502, "upstream request failed", "upstream_error");
    }

    if (proxy) {
      try {
        return await sendViaProxy({
          ...egress,
          proxy,
          timeoutMs: positiveInt(
            env.CODEX_PROXY_TUNNEL_TIMEOUT_MS,
            DEFAULT_TUNNEL_TIMEOUT_MS,
          ),
        });
      } catch (error) {
        // Generic messages only: tunnel errors quote proxy hostnames and
        // handshake detail that must not reach the client.
        if (error instanceof ProxyError && error.code === "proxy_timeout") {
          return errorResponse(504, "proxy egress timed out", "proxy_timeout");
        }
        return errorResponse(502, "proxy egress failed", "proxy_unavailable");
      }
    }

    try {
      return await sendDirect(egress);
    } catch {
      return errorResponse(502, "upstream request failed", "upstream_error");
    }
  },
};

export default worker satisfies ExportedHandler<Env>;
