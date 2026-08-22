/**
 * Which Anthropic endpoint a request is aimed at.
 *
 * The distinction is load-bearing rather than cosmetic. `count_tokens` carries
 * its own beta value, appended by the SDK's token-counting helper instead of by
 * the request builder, so treating it as an ordinary `messages` call would send
 * the wrong beta set in both directions -- missing `token-counting-2024-11-01`
 * and asserting the `/v1/messages` values it never sends.
 *
 * Everything else classifies as `other`, which means "shape nothing". A body
 * this Worker does not recognise is forwarded byte-for-byte: rewriting an
 * unfamiliar shape risks corrupting a request that would otherwise have worked.
 */
import type { ClaudeEndpoint } from "./beta";

/**
 * Classify the *upstream* path.
 *
 * The Worker's own path is `/<hostname>/<upstream-path>`, so the first segment
 * is the routing host and is dropped before matching. Matching is anchored to
 * the end of the path and the query string is ignored, since the real client
 * appends `?beta=true` to both endpoints.
 *
 * Trailing slashes are tolerated because a caller composing the URL by hand may
 * well add one, and it addresses the same endpoint.
 */
export function classifyEndpoint(pathname: string): ClaudeEndpoint {
  // Drop the leading slash and the hostname segment.
  const firstSlash = pathname.indexOf("/", 1);
  const upstreamPath = firstSlash === -1 ? "/" : pathname.slice(firstSlash);
  const normalized = upstreamPath.replace(/\/+$/, "");

  // Checked before the messages case: `/v1/messages/count_tokens` also ends
  // with a segment under `/v1/messages`, so the more specific match must win.
  if (normalized.endsWith("/v1/messages/count_tokens")) {
    return "count_tokens";
  }
  if (normalized.endsWith("/v1/messages")) {
    return "messages";
  }
  return "other";
}
