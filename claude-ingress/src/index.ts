/**
 * Claude ingress.
 *
 * This package is a standalone deployment artifact: it carries its own copy of
 * the relay pipeline, signing and target code, so it installs, tests, builds
 * and deploys without the Codex package present. The two copies are kept in
 * step by the cross-language conformance gate (protocol/conformance.py), which
 * drives both TypeScript implementations over the same vectors as the Rust
 * relay -- a shared source directory would have coupled the deployments
 * instead.
 *
 * Same egress guarantees as the Codex Worker: open to clients, mandatory relay,
 * bounded upstreams. Both ingresses also project the caller's identity, but for
 * opposite reasons, and the two projections must not be confused.
 *
 * The Codex Worker projects Codex identity because its callers are not Codex.
 * Here the caller may well be Claude Code, and this ingress *still* rebuilds the
 * client profile -- see src/cloak. Forwarding the caller's own profile was the
 * previous behaviour and it does not hold up: an arbitrary caller sends an
 * arbitrary mix of CLI version, SDK version, OS, arch and session identity, so
 * traffic through one credential presents as several inconsistent machines. One
 * pinned profile, rebuilt on every request, presents one coherent client.
 *
 * The rebuild is bounded on purpose. It never touches `x-api-key` or
 * `authorization` -- upstream authorization stays the caller's, and this Worker
 * holds no credential to substitute. It shapes only the request surface: identity
 * headers, `anthropic-beta` derived from the body's own capabilities, the billing
 * attribution block at the head of `system`, and `metadata.user_id`. It is
 * idempotent, so a request crossing more than one hop is shaped once, not twice.
 *
 * What it deliberately does not add: the Claude Code identity sentence, a
 * `# currentDate` reminder and cache breakpoints. Those are instructions or
 * caller-owned cache policy, and the attribution block already buys admission
 * without them -- see src/cloak/body.ts.
 *
 * Transport is out of scope and cannot be brought in: the relay reaches upstream
 * with rustls over HTTP/2, so the TLS and HTTP/2 fingerprints are the relay's.
 */
import { projectClaudeRequest, type CloakEnv } from "./cloak";
import { createRelayHandler, type PipelineEnv } from "./pipeline";

export interface Env extends PipelineEnv, CloakEnv {
  CLAUDE_PROXY_MAX_BODY_BYTES?: string;
}

const worker = createRelayHandler<Env>({
  maxBodyBytes: (env) => env.CLAUDE_PROXY_MAX_BODY_BYTES,
  projectRequest: (request, body, env) => projectClaudeRequest(request, body, env),
});

export default worker satisfies ExportedHandler<Env>;
