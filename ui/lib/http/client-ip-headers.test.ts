import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { forwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

describe("forwardedClientIpHeaders", () => {
  const originalValue = process.env.ATOM_UI_FORWARD_CLIENT_IP_HEADERS;

  beforeEach(() => {
    delete process.env.ATOM_UI_FORWARD_CLIENT_IP_HEADERS;
  });

  afterEach(() => {
    if (originalValue === undefined) {
      delete process.env.ATOM_UI_FORWARD_CLIENT_IP_HEADERS;
    } else {
      process.env.ATOM_UI_FORWARD_CLIENT_IP_HEADERS = originalValue;
    }
  });

  it("does not forward client IP headers by default", () => {
    const request = requestWithHeaders();

    expect(forwardedClientIpHeaders(request)).toEqual({});
  });

  it("forwards client IP headers when explicitly enabled", () => {
    process.env.ATOM_UI_FORWARD_CLIENT_IP_HEADERS = "true";
    const request = requestWithHeaders();

    expect(forwardedClientIpHeaders(request)).toEqual({
      "x-forwarded-for": "198.51.100.10",
      "x-real-ip": "198.51.100.11",
      forwarded: "for=198.51.100.12;proto=https",
    });
  });
});

function requestWithHeaders() {
  return new Request("http://localhost/api/graphql", {
    headers: {
      forwarded: "for=198.51.100.12;proto=https",
      "x-forwarded-for": "198.51.100.10",
      "x-real-ip": "198.51.100.11",
    },
  });
}
