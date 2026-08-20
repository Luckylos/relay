import type { TargetRequest } from "../target";
import { projectResponseHeaders } from "../headers";

export interface DirectRequest {
  target: TargetRequest;
  method: string;
  headers: Headers;
  body: Uint8Array;
}

export async function sendDirect(request: DirectRequest): Promise<Response> {
  const upstream = await fetch(request.target.url.toString(), {
    method: request.method,
    headers: request.headers,
    body:
      request.body.byteLength > 0
        ? (request.body as unknown as BodyInit)
        : undefined,
    redirect: "manual",
  });

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: projectResponseHeaders(upstream.headers),
  });
}
