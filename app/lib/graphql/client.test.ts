import { describe, expect, it, vi } from "vitest";
import {
  AtomGraphqlError,
  graphqlClient,
  isForbiddenError,
} from "@/lib/graphql/client";

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

  it("normalizes GraphQL errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ errors: [{ message: "denied" }] })),
    );

    await expect(
      graphqlClient({ query: "{ entities { total } }" }),
    ).rejects.toBeInstanceOf(AtomGraphqlError);
  });

  it("detects forbidden GraphQL errors", () => {
    expect(
      isForbiddenError(new AtomGraphqlError([{ message: "forbidden" }])),
    ).toBe(true);
    expect(
      isForbiddenError(
        new AtomGraphqlError([
          { message: "forbidden" },
          { message: "forbidden" },
        ]),
      ),
    ).toBe(true);
    expect(
      isForbiddenError(new AtomGraphqlError([{ message: "denied" }])),
    ).toBe(false);
  });
});
