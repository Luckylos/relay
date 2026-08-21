/**
 * Codex ingress.
 *
 * Synthesizes Codex identity before egress: the callers are not Codex, but the
 * upstream channel gates on Codex-shaped traffic, so `user-agent`, `originator`,
 * the `x-codex-*` header set and a `client_metadata` body field are projected
 * from one resolved identity. Keeping header and body projection behind a single
 * `ResolvedIdentity` is what prevents the two from drifting apart, which is
 * exactly the mismatch a deep-inspection gate keys on.
 *
 * Everything else -- the relay envelope, signing, target parsing, bounded body,
 * redirect rewriting -- is the shared pipeline.
 */
import { readIdentityConfig, type IdentityEnv, type IdentityConfig } from "./config";
import { projectIdentity, resolveIdentity } from "./identity";
import { createRelayHandler, type PipelineEnv } from "./pipeline";

export interface Env extends IdentityEnv, PipelineEnv {
  CODEX_PROXY_MAX_BODY_BYTES?: string;
}

/**
 * Parsed once per `env` object rather than per request. The Workers runtime
 * reuses the same `env` across requests in an isolate, so this keeps identity
 * config parsing off the hot path without introducing cross-isolate state.
 */
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

const worker = createRelayHandler<Env>({
  maxBodyBytes: (env) => env.CODEX_PROXY_MAX_BODY_BYTES,
  projectRequest: (request, body, env) => {
    const identity = resolveIdentity(request.headers, identityConfig(env));
    return {
      headers: projectIdentity(identity, request.headers),
      body: identity.ensureBodyMetadata(request.headers.get("content-type"), body),
    };
  },
});

export default worker satisfies ExportedHandler<Env>;
