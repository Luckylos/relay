/**
 * Claude ingress.
 *
 * Same egress guarantees as the Codex Worker -- open to clients, mandatory
 * relay, bounded upstreams -- with one deliberate difference: the client's own
 * identity is forwarded untouched.
 *
 * The Codex Worker synthesizes identity because its callers are not Codex and
 * the upstream channel expects Codex-shaped traffic. Here the real client *is*
 * Claude Code, and it already sends its own `user-agent`, `anthropic-version`,
 * `anthropic-beta` and `x-api-key`. Rewriting any of that would replace correct
 * identity with a guess, and injecting a body field would corrupt a request the
 * client composed itself. Omitting `projectRequest` is therefore the whole
 * difference between the two ingresses: headers and body go upstream as sent,
 * with only the headers that must not travel removed -- hop-by-hop, Cloudflare
 * source-revealing, and the relay's own control prefix, all stripped inside
 * `sendViaRelay`.
 */
import { createRelayHandler, type PipelineEnv } from "../pipeline";

export interface Env extends PipelineEnv {
  CLAUDE_PROXY_MAX_BODY_BYTES?: string;
}

const worker = createRelayHandler<Env>({
  maxBodyBytes: (env) => env.CLAUDE_PROXY_MAX_BODY_BYTES,
});

export default worker satisfies ExportedHandler<Env>;
