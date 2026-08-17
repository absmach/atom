/**
 * Reverse policy lookup: "who is this object shared with".
 *
 * `directPolicies(objectId:)` returns only the direct policies whose permission
 * block *names* the object — by id, by object group, or through a group
 * hierarchy scope. Blocks that reach the object without naming it (platform,
 * tenant, objectKind, objectType) and any role-derived access are excluded by
 * the server, so this is a sharing list, not effective access.
 */

/** The object kinds the inspect sheets ask about. */
export type AccessObjectKind = "entity" | "resource";

export type DirectPolicyAction = {
  name: string;
};

export type DirectPolicyPermissionBlock = {
  id: string;
  scopeMode?: string | null;
  groupId?: string | null;
  effect: string;
  actions: DirectPolicyAction[];
};

export type DirectPolicyRow = {
  id: string;
  subjectKind: string;
  subjectId: string;
  createdAt: string;
  permissionBlock: DirectPolicyPermissionBlock;
};

export type DirectPolicyPage = {
  total: number;
  items: DirectPolicyRow[];
};

export const DIRECT_POLICIES_FOR_OBJECT_QUERY = `
  query DirectPoliciesForObject($objectId: ID!, $objectKind: String!, $limit: Int!, $offset: Int!) {
    directPolicies(objectId: $objectId, objectKind: $objectKind, limit: $limit, offset: $offset) {
      total
      items {
        id
        subjectKind
        subjectId
        createdAt
        permissionBlock {
          id
          scopeMode
          groupId
          effect
          actions { name }
        }
      }
    }
  }
`;

/**
 * CRUD resource key to the `objectKind` string the server parses. The accepted
 * values are lowercase (`parse_object_kind`), so "Entity" would be rejected.
 */
export function objectKindForResourceKey(
  resourceKey: string,
): AccessObjectKind | null {
  if (resourceKey === "entities") return "entity";
  if (resourceKey === "resources") return "resource";
  return null;
}

export function isGroupSubject(subjectKind: string) {
  return subjectKind.toLowerCase() === "group";
}

/** Subject ids split by kind, ready for `useNameMap`. */
export function directPolicySubjectIds(policies: DirectPolicyRow[]) {
  const entityIds: string[] = [];
  const groupIds: string[] = [];

  for (const policy of policies) {
    if (!policy.subjectId) continue;
    if (isGroupSubject(policy.subjectKind)) groupIds.push(policy.subjectId);
    else entityIds.push(policy.subjectId);
  }

  return { entityIds, groupIds };
}

/** Object groups named by the returned blocks, so their names resolve too. */
export function directPolicyScopeGroupIds(policies: DirectPolicyRow[]) {
  const groupIds = policies
    .map((policy) => policy.permissionBlock.groupId)
    .filter((id): id is string => Boolean(id));
  return [...new Set(groupIds)];
}

/**
 * Why this policy shows up for this object — the block's scope mode read from
 * the object's side rather than the grant's side.
 */
export function directPolicyReachLabel(
  block: DirectPolicyPermissionBlock,
  groupName?: string,
) {
  const group = groupName || block.groupId || "its object group";

  switch (block.scopeMode) {
    case "object":
      return "This object directly";
    case "group":
      return "This object group";
    case "group_direct_objects":
      return `Direct members of ${group}`;
    case "group_descendant_objects":
      return `Members of ${group} and its descendants`;
    case "group_child_groups":
      return `Child groups of ${group}`;
    case "group_descendant_groups":
      return `Descendant groups of ${group}`;
    default:
      return block.scopeMode ?? "Named by this permission block";
  }
}

export function directPolicyActionNames(block: DirectPolicyPermissionBlock) {
  return block.actions.map((action) => action.name);
}
