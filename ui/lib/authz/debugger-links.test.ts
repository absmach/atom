import { describe, expect, it } from "vitest";
import {
  authzDebuggerHref,
  parseAuthzDebuggerInitialValues,
} from "@/lib/authz/debugger-links";

describe("authorization debugger links", () => {
  it("builds an entity-subject debugger link", () => {
    expect(authzDebuggerHref({ subjectId: "entity-1" })).toBe(
      "/authz?subjectId=entity-1",
    );
  });

  it("builds a resource-target debugger link", () => {
    expect(
      authzDebuggerHref({
        targetKind: "resource",
        targetId: "resource-1",
      }),
    ).toBe("/authz?targetKind=resource&targetId=resource-1");
  });

  it("parses valid initial values and ignores an invalid target kind", () => {
    expect(
      parseAuthzDebuggerInitialValues({
        subjectId: ["entity-1", "entity-2"],
        targetKind: "invalid",
        targetId: "resource-1",
      }),
    ).toEqual({
      subjectId: "entity-1",
      targetId: "resource-1",
    });
  });
});
