import { describe, expect, it } from "vitest";
import {
  candidatesQuery,
  memberDisplayName,
  memberIdVariableName,
  memberKindLabel,
  memberKindTitle,
  membershipMutation,
  membershipQuery,
  membershipVariables,
  membersQuery,
  OBJECT_GROUPS_QUERY,
  objectGroupIdsFromRow,
} from "@/lib/object-groups/membership";

describe("object group ids from a row", () => {
  it("reads the ids the list query already selected", () => {
    expect(
      objectGroupIdsFromRow({
        id: "entity-1",
        objectGroupIds: ["group-1", "group-2"],
      }),
    ).toEqual(["group-1", "group-2"]);
  });

  it("drops duplicates, blanks, and non-string ids", () => {
    expect(
      objectGroupIdsFromRow({
        objectGroupIds: ["group-1", "group-1", "", null, 7, "group-2"],
      }),
    ).toEqual(["group-1", "group-2"]);
  });

  it("returns nothing when the row has no membership", () => {
    expect(objectGroupIdsFromRow(null)).toEqual([]);
    expect(objectGroupIdsFromRow(undefined)).toEqual([]);
    expect(objectGroupIdsFromRow({ id: "entity-1" })).toEqual([]);
    expect(objectGroupIdsFromRow({ objectGroupIds: "group-1" })).toEqual([]);
  });
});

describe("membership mutation variables", () => {
  it("names the member argument per kind", () => {
    expect(memberIdVariableName("entity")).toBe("entityId");
    expect(memberIdVariableName("resource")).toBe("resourceId");
  });

  it("carries the group id for add and remove", () => {
    expect(membershipVariables("entity", "entity-1", "group-1")).toEqual({
      entityId: "entity-1",
      objectGroupId: "group-1",
    });
    expect(membershipVariables("resource", "resource-1", "group-1")).toEqual({
      resourceId: "resource-1",
      objectGroupId: "group-1",
    });
  });

  it("omits the group id when clearing every membership", () => {
    expect(membershipVariables("entity", "entity-1")).toEqual({
      entityId: "entity-1",
    });
  });
});

describe("membership documents", () => {
  it("picks the entity mutations", () => {
    expect(membershipMutation("entity", "add")).toContain(
      "addEntityToObjectGroup(entityId: $entityId, objectGroupId: $objectGroupId)",
    );
    expect(membershipMutation("entity", "remove")).toContain(
      "removeEntityFromObjectGroup(entityId: $entityId, objectGroupId: $objectGroupId)",
    );
    expect(membershipMutation("entity", "clear")).toContain(
      "clearEntityObjectGroups(entityId: $entityId)",
    );
  });

  it("picks the resource mutations", () => {
    expect(membershipMutation("resource", "add")).toContain(
      "addResourceToObjectGroup(resourceId: $resourceId, objectGroupId: $objectGroupId)",
    );
    expect(membershipMutation("resource", "remove")).toContain(
      "removeResourceFromObjectGroup(resourceId: $resourceId, objectGroupId: $objectGroupId)",
    );
    expect(membershipMutation("resource", "clear")).toContain(
      "clearResourceObjectGroups(resourceId: $resourceId)",
    );
  });

  it("returns the updated membership so no refetch is needed", () => {
    for (const kind of ["entity", "resource"] as const) {
      for (const operation of ["add", "remove", "clear"] as const) {
        const document = membershipMutation(kind, operation);
        expect(document).toContain("result:");
        expect(document).toContain("objectGroupIds");
      }
    }
  });

  it("lists members through the parentGroupId list filter", () => {
    expect(membersQuery("entity")).toContain(
      "list: entities(parentGroupId: $groupId",
    );
    expect(membersQuery("resource")).toContain(
      "list: resources(parentGroupId: $groupId",
    );
  });

  it("reads status only for entities, which alone have one", () => {
    expect(membersQuery("entity")).toContain("status");
    expect(membersQuery("resource")).not.toContain("status");
    expect(candidatesQuery("resource")).not.toContain("status");
  });

  it("scopes add pickers by tenant and search term", () => {
    expect(candidatesQuery("entity")).toContain(
      "list: entities(tenantId: $tenantId, q: $q",
    );
    expect(candidatesQuery("resource")).toContain(
      "list: resources(tenantId: $tenantId, q: $q",
    );
  });

  it("reads a single member's membership set", () => {
    expect(membershipQuery("entity")).toContain(
      "member: entity(id: $id) { id objectGroupIds }",
    );
    expect(membershipQuery("resource")).toContain(
      "member: resource(id: $id) { id objectGroupIds }",
    );
  });

  it("picks groups through objectGroups so principal groups never appear", () => {
    expect(OBJECT_GROUPS_QUERY).toContain("objectGroups(tenantId: $tenantId");
    expect(OBJECT_GROUPS_QUERY).not.toMatch(/\bgroups\(/);
  });
});

describe("member labels", () => {
  it("falls back to the id when a resource has no name", () => {
    expect(memberDisplayName({ id: "resource-1", name: null })).toBe(
      "resource-1",
    );
    expect(memberDisplayName({ id: "resource-1", name: "   " })).toBe(
      "resource-1",
    );
    expect(memberDisplayName({ id: "resource-1", name: "Telemetry" })).toBe(
      "Telemetry",
    );
  });

  it("counts members in the right plural", () => {
    expect(memberKindLabel("entity", 0)).toBe("0 entities");
    expect(memberKindLabel("entity", 1)).toBe("1 entity");
    expect(memberKindLabel("entity", 4)).toBe("4 entities");
    expect(memberKindLabel("resource", 1)).toBe("1 resource");
    expect(memberKindLabel("resource", 2)).toBe("2 resources");
  });

  it("titles each members section", () => {
    expect(memberKindTitle("entity")).toBe("Entities");
    expect(memberKindTitle("resource")).toBe("Resources");
  });
});
