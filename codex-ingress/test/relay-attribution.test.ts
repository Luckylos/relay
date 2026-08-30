import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { projectResponseHeaders } from "../src/headers";
import { attributeRelayResponse } from "../src/relay/attribution";

let errorLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  errorLog.mockRestore();
});

function attribute(upstream: Response): Response {
  return attributeRelayResponse(upstream, projectResponseHeaders);
}

/**
 * Attribution is read from whichever namespace the relay answered in.
 *
 * The relay and this Worker deploy independently, so all three shapes are live
 * across the migration. Testing every shape prevents a one-namespace read from
 * turning the other relay generation into a total fail-closed outage.
 */
describe.each([
  ["current-only", ["x-egress-relay-"]],
  ["legacy-only", ["x-codex-relay-"]],
  ["dual-stamping", ["x-egress-relay-", "x-codex-relay-"]],
] as const)("relay response attribution from a %s relay", (_shape, prefixes) => {
  function control(fields: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const prefix of prefixes) {
      for (const [field, value] of Object.entries(fields)) {
        headers[`${prefix}${field}`] = value;
      }
    }
    return headers;
  }

  function relayError(status: number, machineCode: string): Response {
    return new Response(
      JSON.stringify({ error: { type: machineCode, message: "relay request rejected" } }),
      {
        status,
        headers: {
          "content-type": "application/json",
          ...control({ result: "error", error: machineCode, "request-id": "abc123" }),
        },
      },
    );
  }

  it.each([
    [401, "relay_auth_error"],
    [409, "relay_replay"],
    [413, "relay_body_too_large"],
    [400, "relay_protocol_error"],
    [500, "relay_internal_error"],
  ])("maps relay-generated %i %s to 502 relay_unavailable", async (status, code) => {
    const response = attribute(relayError(status, code));

    expect(response.status, `relay ${status} must not reach the client`).toBe(502);
    const body = (await response.json()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe("relay_unavailable");
    expect(JSON.stringify(body)).not.toContain(code);
  });

  it("logs relay attribution metadata without logging the relay body", () => {
    const response = attribute(
      new Response("sensitive relay response body", {
        status: 401,
        headers: {
          "cf-ray": "ray123-SIN",
          ...control({
            result: "error",
            error: "relay_auth_error",
            "request-id": "relay-request-123",
          }),
        },
      }),
    );

    expect(response.status).toBe(502);
    expect(errorLog).toHaveBeenCalledExactlyOnceWith(
      JSON.stringify({
        event: "relay_attribution_failure",
        relay_status: 401,
        relay_result: "error",
        relay_error: "relay_auth_error",
        relay_request_id: "relay-request-123",
        cf_ray: "ray123-SIN",
      }),
    );
    expect(errorLog.mock.calls[0]?.[0]).not.toContain("sensitive relay response body");
  });

  it("maps actionable relay failures without exposing the machine code", async () => {
    const timeout = attribute(relayError(504, "relay_upstream_timeout"));
    expect(timeout.status).toBe(504);
    expect(((await timeout.json()) as { error: { type: string } }).error.type).toBe(
      "upstream_timeout",
    );

    const failed = attribute(relayError(502, "relay_upstream_error"));
    expect(failed.status).toBe(502);
    expect(((await failed.json()) as { error: { type: string } }).error.type).toBe(
      "upstream_error",
    );
  });

  it("maps relay saturation to 503 relay_busy", async () => {
    const busy = attribute(relayError(503, "relay_busy"));
    expect(busy.status).toBe(503);
    expect(((await busy.json()) as { error: { type: string } }).error.type).toBe("relay_busy");
  });

  it.each([400, 401, 404, 429, 500, 502, 503])(
    "returns a genuine upstream %i verbatim",
    async (status) => {
      const upstream = new Response(JSON.stringify({ error: { message: "from upstream" } }), {
        status,
        headers: {
          "content-type": "application/json",
          ...control({ result: "upstream", "request-id": "abc123" }),
        },
      });

      const response = attribute(upstream);

      expect(response.status, "an upstream status belongs to the upstream").toBe(status);
      const body = (await response.json()) as { error: { message: string } };
      expect(body.error.message).toBe("from upstream");
    },
  );

  it("never leaks relay control headers to the client", () => {
    for (const upstream of [
      relayError(401, "relay_auth_error"),
      new Response("ok", {
        status: 200,
        headers: control({ result: "upstream", "request-id": "abc123" }),
      }),
    ]) {
      const response = attribute(upstream);
      for (const [name] of response.headers) {
        expect(name.toLowerCase(), `${name} must not reach the client`).not.toMatch(
          /^x-(egress|codex)-relay-/,
        );
      }
    }
  });
});

describe("relay attribution diagnostics", () => {
  it("logs missing attribution fields as null", () => {
    const response = attribute(
      new Response("edge error body", {
        status: 502,
        headers: { "cf-ray": "edge456-SIN" },
      }),
    );

    expect(response.status).toBe(502);
    expect(errorLog).toHaveBeenCalledExactlyOnceWith(
      JSON.stringify({
        event: "relay_attribution_failure",
        relay_status: 502,
        relay_result: null,
        relay_error: null,
        relay_request_id: null,
        cf_ray: "edge456-SIN",
      }),
    );
    expect(errorLog.mock.calls[0]?.[0]).not.toContain("edge error body");
  });

  it("prefers current control metadata over legacy values", () => {
    const headers = new Headers({
      "x-egress-relay-result": "ERROR",
      "x-egress-relay-error": "RELAY_AUTH_ERROR",
      "x-egress-relay-request-id": "current-request",
      "x-codex-relay-result": "upstream",
      "x-codex-relay-error": "relay_protocol_error",
      "x-codex-relay-request-id": "legacy-request",
    });

    attribute(new Response("rejected", { status: 401, headers }));

    expect(errorLog).toHaveBeenCalledExactlyOnceWith(
      JSON.stringify({
        event: "relay_attribution_failure",
        relay_status: 401,
        relay_result: "error",
        relay_error: "relay_auth_error",
        relay_request_id: "current-request",
        cf_ray: null,
      }),
    );
  });

  it("normalizes blank current metadata to null without legacy fallback", () => {
    const headers = new Headers({
      "x-egress-relay-result": "   ",
      "x-egress-relay-error": "   ",
      "x-egress-relay-request-id": "   ",
      "x-codex-relay-result": "upstream",
      "x-codex-relay-error": "relay_protocol_error",
      "x-codex-relay-request-id": "legacy-request",
      "cf-ray": "   ",
    });

    attribute(new Response("rejected", { status: 401, headers }));

    expect(errorLog).toHaveBeenCalledExactlyOnceWith(
      JSON.stringify({
        event: "relay_attribution_failure",
        relay_status: 401,
        relay_result: null,
        relay_error: null,
        relay_request_id: null,
        cf_ray: null,
      }),
    );
  });

  it("does not log genuine upstream responses", () => {
    const response = attribute(
      new Response("upstream", {
        status: 502,
        headers: { "x-egress-relay-result": "upstream" },
      }),
    );

    expect(response.status).toBe(502);
    expect(errorLog).not.toHaveBeenCalled();
  });
});
