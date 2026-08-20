export const RESPONSE_HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
] as const;

export function projectResponseHeaders(incoming: Headers): Headers {
  const output = new Headers();
  for (const [name, value] of incoming) {
    if (
      RESPONSE_HOP_BY_HOP_HEADERS.includes(
        name as (typeof RESPONSE_HOP_BY_HOP_HEADERS)[number],
      )
    ) {
      continue;
    }
    output.set(name, value);
  }
  return output;
}
