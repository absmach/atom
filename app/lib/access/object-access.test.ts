import { describe, expect, it } from "vitest";
import {
  DIRECT_POLICIES_FOR_OBJECT_QUERY,
  type DirectPolicyRow,
  directPolicyActionNames,
  directPolicyReachLabel,
  directPolicyScopeGroupIds,
  directPolicySubjectIds,
  isGroupSubject,
  objectKindForResourceKey,
} from "@/lib/access/object-access";

function policy(overrides: Partial<DirectPolicyRow> = {}): DirectPolicyRow {
  return {
    id: "policy-1",
    subjectKind: "entity",
    subjectId: "entity-1",
    createdAt: "2026-01-01T00:00:00Z",
    permissionBlock: {
      id: "block-1",
      scopeMode: "object",
      groupId: null,
      effect: "allow",
      actions: [{ name: "read" }],
    },
    ...overrides,
  };
}

describe("object kind for the inspect sheet", () => {
  it("maps the two CRUD keys to the kinds the server parses", () => {
    expect(objectKindForResourceKey("entities")).toBe("entity");
    expect(objectKindForResourceKey("resources")).toBe("resource");
  });

  it("has no object kind for other resources", () => {
    expect(objectKindForResourceKey("groups")).toBeNull();
    expect(objectKindForResourceKey("policies")).toBeNull();
  });
});

describe("direct policy subjects", () => {
  it("recognises group subjects regardless of casing", () => {
    expect(isGroupSubject("group")).toBe(true);
    expect(isGroupSubject("GROUP")).toBe(true);
    expect(isGroupSubject("entity")).toBe(false);
  });

  it("splits subject ids by kind for name resolution", () => {
    expect(
      directPolicySubjectIds([
        policy(),
        policy({ id: "policy-2", subjectKind: "group", subjectId: "group-1" }),
        policy({ id: "policy-3", subjectId: "entity-2" }),
      ]),
    ).toEqual({
      entityIds: ["entity-1", "entity-2"],
      groupIds: ["group-1"],
    });
  });

  it("skips policies without a subject id", () => {
    expect(directPolicySubjectIds([policy({ subjectId: "" })])).toEqual({
      entityIds: [],
      groupIds: [],
    });
  });

  it("collects the object groups the blocks name, without duplicates", () => {
    expect(
      directPolicyScopeGroupIds([
        policy(),
        policy({
          id: "policy-2",
          permissionBlock: {
            id: "block-2",
            scopeMode: "group_direct_objects",
            groupId: "group-1",
            effect: "allow",
            actions: [],
          },
        }),
        policy({
          id: "policy-3",
          permissionBlock: {
            id: "block-3",
            scopeMode: "group_descendant_objects",
            groupId: "group-1",
            effect: "allow",
            actions: [],
          },
        }),
      ]),
    ).toEqual(["group-1"]);
  });
});

describe("why a policy reaches this object", () => {
  function block(scopeMode: string, groupId: string | null = "group-1") {
    return {
      id: "block-1",
      scopeMode,
      groupId,
      effect: "allow",
      actions: [],
    };
  }

  it("describes an object-scoped grant", () => {
    expect(directPolicyReachLabel(block("object", null))).toBe(
      "This object directly",
    );
  });

  it("describes a grant on the group itself", () => {
    expect(directPolicyReachLabel(block("group"))).toBe("This object group");
  });

  it("names the group a membership scope came through", () => {
    expect(
      directPolicyReachLabel(block("group_direct_objects"), "Floor sensors"),
    ).toBe("Direct members of Floor sensors");
    expect(
      directPolicyReachLabel(
        block("group_descendant_objects"),
        "Floor sensors",
      ),
    ).toBe("Members of Floor sensors and its descendants");
    expect(
      directPolicyReachLabel(block("group_child_groups"), "Floor sensors"),
    ).toBe("Child groups of Floor sensors");
    expect(
      directPolicyReachLabel(block("group_descendant_groups"), "Floor sensors"),
    ).toBe("Descendant groups of Floor sensors");
  });

  it("falls back to the group id, then to a generic phrase", () => {
    expect(directPolicyReachLabel(block("group_direct_objects"))).toBe(
      "Direct members of group-1",
    );
    expect(directPolicyReachLabel(block("group_direct_objects", null))).toBe(
      "Direct members of its object group",
    );
  });

  it("shows an unknown scope mode as-is", () => {
    expect(directPolicyReachLabel(block("something_new"))).toBe(
      "something_new",
    );
  });
});

describe("direct policy actions", () => {
  it("lists the granted action names", () => {
    expect(
      directPolicyActionNames({
        id: "block-1",
        scopeMode: "object",
        groupId: null,
        effect: "allow",
        actions: [{ name: "read" }, { name: "write" }],
      }),
    ).toEqual(["read", "write"]);
  });
});

describe("the reverse lookup query", () => {
  it("filters by object id and kind", () => {
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain(
      "directPolicies(objectId: $objectId, objectKind: $objectKind",
    );
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain("$objectKind: String!");
  });

  it("selects the subject and its permission block", () => {
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain("subjectKind");
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain("subjectId");
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain("permissionBlock");
    expect(DIRECT_POLICIES_FOR_OBJECT_QUERY).toContain("actions { name }");
  });
});
