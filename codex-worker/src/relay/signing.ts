import {
  base64UrlEncode,
  buildCanonicalRequest,
  type RelaySigningInput,
  utf8,
} from "./protocol";

export async function sha256Base64Url(body: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", body as BufferSource);
  return base64UrlEncode(new Uint8Array(digest));
}

export async function signRelayRequest(
  input: RelaySigningInput,
  secret: string | Uint8Array,
): Promise<string> {
  const keyBytes = typeof secret === "string" ? utf8(secret) : secret;
  const bodySha256 = await sha256Base64Url(input.body);
  const canonical = buildCanonicalRequest(input, bodySha256);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, utf8(canonical) as BufferSource);
  return base64UrlEncode(new Uint8Array(signature));
}
