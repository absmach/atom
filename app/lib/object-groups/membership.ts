/**
 * Object-group membership is many-to-many: an entity or resource belongs to a
 * set of object groups, and a group holds a set of both kinds. Every document
 * and helper here is shared by the group-side panel and the entity/resource
 * side field so the two directions can never drift apart.
 */

export type ObjectMemberKind = "entity" | "resource";

export const OBJECT_MEMBER_KINDS: ObjectMemberKind[] = ["entity", "resource"];

export type ObjectGroupMember = {
  id: string;
  /** `Resource.name` is nullable in the schema, `Entity.name` is not. */
  name?: string | null;
  kind: string;
  /** Entities carry a lifecycle status; resources have no status field. */
  status?: string | null;
  /** Only the add pickers select this, to hide candidates already joined. */
  objectGroupIds?: string[] | null;
};

export type ObjectGroupMemberPage = {
  total: number;
  items: ObjectGroupMember[];
};

export type ObjectGroupOption = {
  id: string;
  name: string;
};

export type ObjectGroupMembership = {
  id: string;
  objectGroupIds: string[];
};

/**
 * Members of one object group, read through the list filters rather than a
 * dedicated query — `parentGroupId` is the supported way to ask this.
 */
const MEMBERS_QUERIES: Record<ObjectMemberKind, string> = {
  entity: `
    query ObjectGroupEntityMembers($groupId: ID!, $limit: Int!, $offset: Int!) {
      list: entities(parentGroupId: $groupId, limit: $limit, offset: $offset) {
        total
        items { id name kind status }
      }
    }
  `,
  resource: `
    query ObjectGroupResourceMembers($groupId: ID!, $limit: Int!, $offset: Int!) {
      list: resources(parentGroupId: $groupId, limit: $limit, offset: $offset) {
        total
        items { id name kind }
      }
    }
  `,
};

/**
 * Search-to-add pickers, scoped to the group's tenant. `objectGroupIds` rides
 * along so the picker can drop candidates already in the group without a
 * second round trip.
 */
const CANDIDATES_QUERIES: Record<ObjectMemberKind, string> = {
  entity: `
    query ObjectGroupEntityCandidates($tenantId: ID, $q: String, $limit: Int!) {
      list: entities(tenantId: $tenantId, q: $q, limit: $limit, offset: 0) {
        total
        items { id name kind status objectGroupIds }
      }
    }
  `,
  resource: `
    query ObjectGroupResourceCandidates($tenantId: ID, $q: String, $limit: Int!) {
      list: resources(tenantId: $tenantId, q: $q, limit: $limit, offset: 0) {
        total
        items { id name kind objectGroupIds }
      }
    }
  `,
};

const MEMBERSHIP_QUERIES: Record<ObjectMemberKind, string> = {
  entity: `
    query EntityObjectGroups($id: ID!) {
      member: entity(id: $id) { id objectGroupIds }
    }
  `,
  resource: `
    query ResourceObjectGroups($id: ID!) {
      member: resource(id: $id) { id objectGroupIds }
    }
  `,
};

/**
 * The type-filtered convenience query, so principal groups can never show up
 * in an object-group picker.
 */
export const OBJECT_GROUPS_QUERY = `
  query ObjectGroupPicker($tenantId: ID, $q: String, $limit: Int!, $offset: Int!) {
    objectGroups(tenantId: $tenantId, q: $q, limit: $limit, offset: $offset) {
      total
      items { id name }
    }
  }
`;

export type MembershipOperation = "add" | "remove" | "clear";

/**
 * Each mutation returns the mutated Entity/Resource, so the response carries
 * the authoritative membership set and no refetch is needed. Results are
 * aliased to `result` so callers read one shape for all six mutations.
 */
const MEMBERSHIP_MUTATIONS: Record<
  ObjectMemberKind,
  Record<MembershipOperation, string>
> = {
  entity: {
    add: `
      mutation AddEntityToObjectGroup($entityId: ID!, $objectGroupId: ID!) {
        result: addEntityToObjectGroup(entityId: $entityId, objectGroupId: $objectGroupId) {
          id
          objectGroupIds
        }
      }
    `,
    remove: `
      mutation RemoveEntityFromObjectGroup($entityId: ID!, $objectGroupId: ID!) {
        result: removeEntityFromObjectGroup(entityId: $entityId, objectGroupId: $objectGroupId) {
          id
          objectGroupIds
        }
      }
    `,
    clear: `
      mutation ClearEntityObjectGroups($entityId: ID!) {
        result: clearEntityObjectGroups(entityId: $entityId) {
          id
          objectGroupIds
        }
      }
    `,
  },
  resource: {
    add: `
      mutation AddResourceToObjectGroup($resourceId: ID!, $objectGroupId: ID!) {
        result: addResourceToObjectGroup(resourceId: $resourceId, objectGroupId: $objectGroupId) {
          id
          objectGroupIds
        }
      }
    `,
    remove: `
      mutation RemoveResourceFromObjectGroup($resourceId: ID!, $objectGroupId: ID!) {
        result: removeResourceFromObjectGroup(resourceId: $resourceId, objectGroupId: $objectGroupId) {
          id
          objectGroupIds
        }
      }
    `,
    clear: `
      mutation ClearResourceObjectGroups($resourceId: ID!) {
        result: clearResourceObjectGroups(resourceId: $resourceId) {
          id
          objectGroupIds
        }
      }
    `,
  },
};

export function membersQuery(kind: ObjectMemberKind) {
  return MEMBERS_QUERIES[kind];
}

export function candidatesQuery(kind: ObjectMemberKind) {
  return CANDIDATES_QUERIES[kind];
}

export function membershipQuery(kind: ObjectMemberKind) {
  return MEMBERSHIP_QUERIES[kind];
}

export function membershipMutation(
  kind: ObjectMemberKind,
  operation: MembershipOperation,
) {
  return MEMBERSHIP_MUTATIONS[kind][operation];
}

/** `entityId` / `resourceId` — the mutations do not share an argument name. */
export function memberIdVariableName(kind: ObjectMemberKind) {
  return kind === "entity" ? "entityId" : "resourceId";
}

export function membershipVariables(
  kind: ObjectMemberKind,
  memberId: string,
  objectGroupId?: string,
): Record<string, string> {
  const variables: Record<string, string> = {
    [memberIdVariableName(kind)]: memberId,
  };
  if (objectGroupId !== undefined) {
    variables.objectGroupId = objectGroupId;
  }
  return variables;
}

/**
 * Entity and resource rows already select `objectGroupIds`, so the inspect
 * sheet can seed membership without a round trip.
 */
export function objectGroupIdsFromRow(
  row: Record<string, unknown> | null | undefined,
): string[] {
  if (!row || !Array.isArray(row.objectGroupIds)) return [];
  const ids = row.objectGroupIds.filter(
    (id): id is string => typeof id === "string" && id.length > 0,
  );
  return [...new Set(ids)];
}

/**
 * An add picker must never offer something that is already joined: the add
 * would be a silent no-op, and the row gives no hint that it is redundant.
 * Both directions decide from `objectGroupIds` — the entity/resource side
 * holds its own set, the group side reads each candidate's set.
 */
export function excludeJoinedGroups<T extends { id: string }>(
  options: T[],
  joinedGroupIds: readonly string[],
): T[] {
  const joined = new Set(joinedGroupIds);
  return options.filter((option) => !joined.has(option.id));
}

export function excludeJoinedMembers<
  T extends { objectGroupIds?: string[] | null },
>(candidates: T[], groupId: string): T[] {
  return candidates.filter(
    (candidate) => !candidate.objectGroupIds?.includes(groupId),
  );
}

/** Resource names are nullable; never render an empty label. */
export function memberDisplayName(member: {
  id: string;
  name?: string | null;
}) {
  const name = member.name?.trim();
  return name ? name : member.id;
}

export function memberKindLabel(kind: ObjectMemberKind, count: number) {
  if (count === 1) return `1 ${kind}`;
  return `${count} ${kind === "entity" ? "entities" : "resources"}`;
}

export function memberKindTitle(kind: ObjectMemberKind) {
  return kind === "entity" ? "Entities" : "Resources";
}
