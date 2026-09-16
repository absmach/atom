import { describe, expect, it, vi } from "vitest";
import {
  AtomGraphqlError,
  graphqlClient,
  graphqlClientRaw,
  graphqlErrorCode,
  isForbiddenError,
  isRetryableError,
} from "@/lib/graphql/client";

// Issue #101: every Atom-generated GraphQL error carries extensions.code /
// retryable / requestId. See api/v1/graphql-error-contract.md.

describe("graphqlClient", () => {
  it("returns data for successful GraphQL responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ data: { health: "ok" } })),
    );

    await expect(
      graphqlClient<{ health: string }>({ query: "{ health }" }),
    ).resolves.toEqual({
      health: "ok",
    });
  });

  it("rejects (all-or-nothing) any HTTP 200 response with a non-empty errors array", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          data: { entity: null },
          errors: [
            {
              message: "entity not found",
              extensions: {
                code: "NOT_FOUND",
                retryable: false,
                requestId: "req-1",
              },
            },
          ],
        }),
      ),
    );

    await expect(
      graphqlClient({ query: "{ entities { total } }" }),
    ).rejects.toBeInstanceOf(AtomGraphqlError);
  });

  it("detects FORBIDDEN from extensions.code, never from message text", () => {
    const forbidden = new AtomGraphqlError([
      {
        message: "forbidden",
        extensions: { code: "FORBIDDEN", retryable: false },
      },
    ]);
    expect(isForbiddenError(forbidden)).toBe(true);

    const relabeledMessage = new AtomGraphqlError([
      {
        message: "you cannot do that",
        extensions: { code: "FORBIDDEN", retryable: false },
      },
    ]);
    expect(isForbiddenError(relabeledMessage)).toBe(true);

    // The exact string "forbidden" with a *different* code must not match —
    // proving detection is code-based, not a message string check.
    const misleadingMessage = new AtomGraphqlError([
      {
        message: "forbidden",
        extensions: { code: "BAD_REQUEST", retryable: false },
      },
    ]);
    expect(isForbiddenError(misleadingMessage)).toBe(false);

    const notForbidden = new AtomGraphqlError([
      {
        message: "denied",
        extensions: { code: "CONFLICT", retryable: false },
      },
    ]);
    expect(isForbiddenError(notForbidden)).toBe(false);

    // No extensions at all (e.g. an async-graphql-internal error that somehow
    // never reached the default fallback) must not be misclassified either.
    expect(
      isForbiddenError(new AtomGraphqlError([{ message: "denied" }])),
    ).toBe(false);

    expect(isForbiddenError(new Error("forbidden"))).toBe(false);
    expect(isForbiddenError("forbidden")).toBe(false);
  });

  it("exposes the extensions.code of the first error via graphqlErrorCode", () => {
    const error = new AtomGraphqlError([
      { message: "x", extensions: { code: "CONFLICT", retryable: false } },
    ]);
    expect(graphqlErrorCode(error)).toBe("CONFLICT");
    expect(graphqlErrorCode(new Error("not atom"))).toBeUndefined();
  });

  it("reports retryable via extensions.retryable, not code alone", () => {
    const rateLimited = new AtomGraphqlError([
      {
        message: "slow down",
        extensions: {
          code: "RATE_LIMITED",
          retryable: true,
          retryAfterSeconds: 30,
        },
      },
    ]);
    expect(isRetryableError(rateLimited)).toBe(true);

    const badRequest = new AtomGraphqlError([
      { message: "bad", extensions: { code: "BAD_REQUEST", retryable: false } },
    ]);
    expect(isRetryableError(badRequest)).toBe(false);
  });

  it("makes the correlating requestId available on the thrown client error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          errors: [
            {
              message: "internal error",
              extensions: {
                code: "INTERNAL",
                retryable: false,
                requestId: "2cc55e48-d44f-49ce-99e2-b08f06f619a6",
              },
            },
          ],
        }),
      ),
    );

    try {
      await graphqlClient({ query: "{ health }" });
      expect.unreachable(
        "graphqlClient must throw on a non-empty errors array",
      );
    } catch (error) {
      expect(error).toBeInstanceOf(AtomGraphqlError);
      expect((error as AtomGraphqlError).requestId).toBe(
        "2cc55e48-d44f-49ce-99e2-b08f06f619a6",
      );
    }
  });

  it("normalizes a transport failure with no GraphQL envelope safely, without a fabricated code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );

    const result = await graphqlClientRaw({ query: "{ health }" });
    expect(result.data).toBeNull();
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].extensions?.code).toBeUndefined();
    expect(isForbiddenError(new AtomGraphqlError(result.errors))).toBe(false);
  });

  it("normalizes a non-JSON response body safely", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("<html>not json</html>", {
            status: 502,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const result = await graphqlClientRaw({ query: "{ health }" });
    expect(result.data).toBeNull();
    expect(result.errors.length).toBeGreaterThan(0);
  });
});

describe("graphqlClientRaw", () => {
  it("preserves partial data alongside errors instead of throwing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          data: { health: "ok", entity: null },
          errors: [
            {
              message: "entity not found",
              path: ["entity"],
              extensions: { code: "NOT_FOUND", retryable: false },
            },
          ],
        }),
      ),
    );

    const result = await graphqlClientRaw<{
      health: string;
      entity: null;
    }>({ query: '{ health entity(id: "x") { id } }' });

    expect(result.data).toEqual({ health: "ok", entity: null });
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].extensions?.code).toBe("NOT_FOUND");
  });

  it("returns an empty errors array and the data on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ data: { health: "ok" } })),
    );

    const result = await graphqlClientRaw<{ health: string }>({
      query: "{ health }",
    });
    expect(result.errors).toEqual([]);
    expect(result.data).toEqual({ health: "ok" });
  });
});
