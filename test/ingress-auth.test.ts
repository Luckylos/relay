import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { INGRESS_TOKEN_HEADER, MIN_TOKEN_LENGTH } from "../src/ingress-auth";
import { RELAY_CONTROL_PREFIX, isStrippedRequestHeader } from "../src/headers";
import { base64UrlDecode } from "../src/relay/protocol";

/** 43 base64url chars = 32 random bytes, the production minimum. */
const TOKEN = "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaGk";

const ENV: Env = {
  CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
  INGRESS_AUTH_TOKEN: TOKEN,
  EGRESS_RELAY_URL: "https://relay.internal.example/v1/forward",
  EGRESS_RELAY_KEY_ID: "key-1",
  EGRESS_RELAY_SECRET: "relay-test-secret",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function headerBlock(request: Request): Map<string, string> {
  const raw = request.headers.get("x-codex-relay-headers") ?? "";
  const block = new TextDecoder().decode(base64UrlDecode(raw));
  const parsed = new Map<string, string>();
  for (const line of block.split("\n")) {
    if (line.length === 0) continue;
    const separator = line.indexOf(":");
    parsed.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return parsed;
}

function authorized(headers: Record<string, string> = {}): HeadersInit {
  return { "x-codex-relay-token": TOKEN, ...headers };
}

describe("Worker ingress authentication", () => {
  it("keeps the token header inside the stripped relay-control namespace", () => {
    // The token never reaches the upstream because its name falls under the
    // relay-control prefix. Renaming it outside that namespace would silently
    // start forwarding the ingress credential, so pin the relationship here.
    expect(INGRESS_TOKEN_HEADER.startsWith(RELAY_CONTROL_PREFIX)).toBe(true);
    expect(isStrippedRequestHeader(INGRESS_TOKEN_HEADER)).toBe(true);
    expect(isStrippedRequestHeader(INGRESS_TOKEN_HEADER.toUpperCase())).toBe(true);
    // 32 random bytes in unpadded base64url.
    expect(MIN_TOKEN_LENGTH).toBe(43);
  });

  it("forwards a request that carries the correct token", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models", {
          headers: authorized(),
        }),
        ENV,
        context(),
      );

      expect(response.status).toBe(204);
      expect(upstream).toHaveBeenCalledTimes(1);
    } finally {
      upstream.mockRestore();
    }
  });

  it("rejects missing and wrong tokens with 401 and zero egress", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      const cases: Array<[string, HeadersInit]> = [
        ["missing", {}],
        ["empty", { "x-codex-relay-token": "" }],
        ["wrong value", { "x-codex-relay-token": "not-the-token" }],
        // Same length as the real token, differing in the final character:
        // a non-constant-time comparison would still reject it, but this is the
        // shape an attacker uses to probe for one, so it must stay covered.
        ["near miss", { "x-codex-relay-token": `${TOKEN.slice(0, -1)}X` }],
        ["case mismatch", { "x-codex-relay-token": TOKEN.toLowerCase() }],
        ["token in query instead of header", {}],
      ];

      for (const [label, headers] of cases) {
        const url =
          label === "token in query instead of header"
            ? `https://relay.example/api.example.com/v1/models?token=${TOKEN}`
            : "https://relay.example/api.example.com/v1/models";
        const response = await worker.fetch(new Request(url, { headers }), ENV, context());

        expect(response.status, `${label} must be rejected`).toBe(401);
        // Generic body: it must not reveal whether a token was supplied at all.
        expect(await response.json()).toEqual({
          error: { message: "unauthorized", type: "unauthorized" },
        });
      }

      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });

  it("authenticates before parsing the target so validity is not probeable", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      // An unauthenticated client must not be able to tell a valid target from
      // an invalid one by comparing 400 against 401.
      for (const path of ["not a hostname/x", "api.example.com/v1/models"]) {
        const response = await worker.fetch(
          new Request(`https://relay.example/${path}`),
          ENV,
          context(),
        );
        expect(response.status, path).toBe(401);
      }
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });

  it("fails closed when the ingress token is not configured", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      for (const token of [undefined, "", "too-short-to-be-random"]) {
        const response = await worker.fetch(
          new Request("https://relay.example/api.example.com/v1/models", {
            // Even a client presenting the weak token must not get through.
            headers: token ? { "x-codex-relay-token": token } : {},
          }),
          { ...ENV, INGRESS_AUTH_TOKEN: token },
          context(),
        );

        expect(response.status, `token=${String(token)}`).toBe(502);
        expect(await response.json()).toEqual({
          error: {
            message: "ingress authentication is not configured",
            type: "ingress_misconfigured",
          },
        });
      }
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });
});

describe("Worker request header hygiene", () => {
  it("never forwards the ingress token to the relay or the upstream", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));
    try {
      await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models", {
          headers: authorized(),
        }),
        ENV,
        context(),
      );

      const sent = upstream.mock.calls[0]?.[0] as Request;
      const block = headerBlock(sent);
      expect(block.has("x-codex-relay-token")).toBe(false);
      expect(sent.headers.get("x-codex-relay-token")).toBeNull();
      // The token must not survive anywhere in the signed envelope.
      expect(JSON.stringify([...block])).not.toContain(TOKEN);
      expect(JSON.stringify([...sent.headers])).not.toContain(TOKEN);
    } finally {
      upstream.mockRestore();
    }
  });

  it("strips platform source headers that would leak the client origin", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));
    try {
      await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models", {
          headers: authorized({
            "cf-connecting-ip": "203.0.113.9",
            "cf-ray": "8a1b2c3d4e5f6789-SJC",
            "cf-visitor": '{"scheme":"https"}',
            "cdn-loop": "cloudflare; loops=1",
            forwarded: "for=203.0.113.9;proto=https",
            "x-forwarded-for": "203.0.113.9, 198.51.100.7",
            "x-forwarded-proto": "https",
            "x-real-ip": "203.0.113.9",
            "true-client-ip": "203.0.113.9",
            // A legitimate business header must survive the same pass.
            authorization: "Bearer client-token",
          }),
        }),
        ENV,
        context(),
      );

      const sent = upstream.mock.calls[0]?.[0] as Request;
      const block = headerBlock(sent);
      for (const leaked of [
        "cf-connecting-ip",
        "cf-ray",
        "cf-visitor",
        "cdn-loop",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-real-ip",
        "true-client-ip",
      ]) {
        expect(block.has(leaked), `${leaked} must be stripped`).toBe(false);
      }
      expect(JSON.stringify([...block])).not.toContain("203.0.113.9");
      expect(block.get("authorization")).toBe("Bearer client-token");
    } finally {
      upstream.mockRestore();
    }
  });

  it("signs business and identity headers without echoing them on the outer request", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));
    try {
      await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/responses", {
          method: "POST",
          headers: authorized({
            authorization: "Bearer client-token",
            "content-type": "application/json",
            accept: "text/event-stream",
          }),
          body: '{"model":"gpt-5.6-terra"}',
        }),
        ENV,
        context(),
      );

      const sent = upstream.mock.calls[0]?.[0] as Request;
      const block = headerBlock(sent);

      // Signed block carries the business contract...
      expect(block.get("authorization")).toBe("Bearer client-token");
      expect(block.get("content-type")).toBe("application/json");
      expect(block.get("accept")).toBe("text/event-stream");
      expect(block.get("x-codex-installation-id")).toBe(ENV.CODEX_PROXY_INSTALLATION_ID);
      expect(block.get("session-id")).toBeTruthy();
      expect(block.get("originator")).toBeTruthy();

      // ...while the outer request must not repeat them, so an intermediary
      // normalizing `accept-encoding` cannot invalidate the signature.
      expect(sent.headers.get("authorization")).toBeNull();
      expect(sent.headers.get("accept")).toBeNull();
      expect(sent.headers.get("session-id")).toBeNull();
      expect(sent.headers.get("content-type")).toBe("application/octet-stream");
    } finally {
      upstream.mockRestore();
    }
  });

  it("keeps the existing client_metadata body projection", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));
    try {
      await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/responses", {
          method: "POST",
          headers: authorized({ "content-type": "application/json" }),
          body: '{"model":"gpt-5.6-terra"}',
        }),
        ENV,
        context(),
      );

      const sent = upstream.mock.calls[0]?.[0] as Request;
      const block = headerBlock(sent);
      const body = JSON.parse(new TextDecoder().decode(await sent.arrayBuffer()));

      expect(body).toMatchObject({
        model: "gpt-5.6-terra",
        client_metadata: {
          "x-codex-installation-id": ENV.CODEX_PROXY_INSTALLATION_ID,
          session_id: block.get("session-id"),
          thread_id: block.get("thread-id"),
        },
      });
      // Body digest must cover the projected body, not the original.
      expect(block.has("x-codex-relay-body-sha256")).toBe(false);
      expect(sent.headers.get("x-codex-relay-body-sha256")).toBeTruthy();
    } finally {
      upstream.mockRestore();
    }
  });
});
