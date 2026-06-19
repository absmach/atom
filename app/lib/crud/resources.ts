import type { LucideIcon } from "lucide-react";
import {
  Boxes,
  Braces,
  Building2,
  Fingerprint,
  GitBranch,
  KeyRound,
  Network,
  ScrollText,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Users,
} from "lucide-react";

export type CrudAction = "create" | "read" | "update" | "delete";

export type CrudResource = {
  key: string;
  title: string;
  route: string;
  description: string;
  icon: LucideIcon;
  queryName: string;
  listQuery?: string;
  createMutation?: string;
  deleteMutation?: string;
  deleteIdField?: string;
  formAttributes?: boolean;
  tenantFilter?: boolean;
  filters?: Array<{
    key: string;
    variable?: string;
    label: string;
    type: "text" | "select";
    placeholder?: string;
    options?: Array<{ label: string; value: string }>;
  }>;
  columns: Array<{
    key: string;
    label: string;
    priority?: "high" | "medium" | "low";
  }>;
  sampleRows: Array<Record<string, unknown>>;
  missing: Partial<Record<CrudAction, string>>;
};

export const crudResources: CrudResource[] = [
  {
    key: "tenants",
    title: "Tenants",
    route: "/tenants",
    description:
      "Top-level boundaries for entities, resources, groups, roles, and assignments.",
    icon: Building2,
    queryName: "tenants",
    listQuery: `query Tenants($limit: Int = 50, $offset: Int = 0) { tenants(limit: $limit, offset: $offset) { total items { id name alias tags attributes status createdAt updatedAt } } }`,
    createMutation: `mutation CreateTenant($input: CreateTenantInput!) { createTenant(input: $input) { id name alias tags status createdAt updatedAt } }`,
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "alias", label: "Alias", priority: "medium" },
      { key: "tags", label: "Tags", priority: "medium" },
      { key: "status", label: "Status", priority: "high" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      { id: "global", name: "Global", alias: "-", status: "active" },
    ],
    missing: {},
  },
  {
    key: "entities",
    title: "Entities",
    route: "/entities",
    description:
      "Humans, devices, services, workloads, and applications managed as first-class principals.",
    icon: Fingerprint,
    queryName: "entities",
    tenantFilter: true,
    listQuery: `query Entities($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { entities(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id kind profileId profileVersionId name alias tenantId parentGroupId attributes status createdAt updatedAt } } }`,
    createMutation: `mutation CreateEntity($input: CreateEntityInput!) { createEntity(input: $input) { id kind profileId profileVersionId name alias tenantId status createdAt updatedAt } }`,
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "alias", label: "Alias", priority: "medium" },
      { key: "kind", label: "Kind", priority: "high" },
      { key: "profileId", label: "Profile", priority: "medium" },
      { key: "status", label: "Status", priority: "high" },
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "demo-entity",
        name: "sensor-gateway-01",
        kind: "device",
        status: "active",
        tenantId: "factory-a",
      },
    ],
    missing: {},
  },
  {
    key: "profiles",
    title: "Profiles",
    route: "/profiles",
    description:
      "Schema-backed platform modeling for entities and future object types.",
    icon: Braces,
    queryName: "profiles",
    tenantFilter: true,
    listQuery: `query Profiles($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { profiles(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id objectKind kind key displayName tenantId status createdAt updatedAt } } }`,
    createMutation: `mutation CreateProfile($input: CreateProfileInput!) { createProfile(input: $input) { id objectKind kind key displayName status createdAt updatedAt } }`,
    columns: [
      { key: "displayName", label: "Display name", priority: "high" },
      { key: "objectKind", label: "Object", priority: "medium" },
      { key: "kind", label: "Kind", priority: "medium" },
      { key: "tenantId", label: "Scope", priority: "medium" },
      { key: "status", label: "Status", priority: "high" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "profile-user",
        displayName: "User",
        objectKind: "entity",
        kind: "human",
        status: "active",
      },
    ],
    missing: {},
  },
  {
    key: "groups",
    title: "Groups",
    route: "/groups",
    description:
      "Object Groups define where access applies. Principal Groups collect identities that receive assignments.",
    icon: Users,
    queryName: "groups",
    tenantFilter: true,
    listQuery: `query Groups($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { groups(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id name tenantId groupType parentId description createdAt updatedAt } } }`,
    createMutation: `mutation CreateGroup($input: CreateGroupInput!) { createGroup(input: $input) { id name tenantId groupType description createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteGroup($id: ID!) { deleteGroup(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "groupType", label: "Type", priority: "high" },
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "parentId", label: "Parent", priority: "medium" },
      { key: "description", label: "Description", priority: "low" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "group-ops",
        name: "floor-sensors",
        tenantId: "factory-a",
        description: "Production floor devices",
      },
    ],
    missing: {},
  },
  {
    key: "resources",
    title: "Resources",
    route: "/resources",
    description: "Protected objects evaluated by Atom's online PDP.",
    icon: Server,
    queryName: "resources",
    tenantFilter: true,
    listQuery: `query Resources($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { resources(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id kind name alias tenantId ownerId parentGroupId attributes createdAt updatedAt } } }`,
    createMutation: `mutation CreateResource($input: CreateResourceInput!) { createResource(input: $input) { id kind name alias tenantId ownerId createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteResource($id: ID!) { deleteResource(id: $id) }`,
    deleteIdField: "id",
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "alias", label: "Alias", priority: "medium" },
      { key: "kind", label: "Kind", priority: "high" },
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "ownerId", label: "Owner", priority: "low" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "resource-channel",
        name: "telemetry",
        kind: "channel",
        tenantId: "factory-a",
      },
    ],
    missing: {},
  },
  {
    key: "roles",
    title: "Roles",
    route: "/roles",
    description:
      "Rows from roles: named action sets assigned through policies/assignments.",
    icon: ShieldCheck,
    queryName: "roles",
    tenantFilter: true,
    listQuery: `query Roles($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { roles(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id name tenantId description derivedKind createdAt updatedAt } } }`,
    createMutation: `mutation CreateRole($input: CreateRoleInput!) { createRole(input: $input) { id name tenantId description derivedKind createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteRole($id: ID!) { deleteRole(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "name", label: "Name", priority: "high" },
      { key: "description", label: "Description", priority: "low" },
      { key: "derivedKind", label: "Kind", priority: "high" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "role-publisher",
        name: "publisher",
        tenantId: "factory-a",
        description: "Can publish telemetry",
      },
    ],
    missing: {},
  },
  {
    key: "permission-blocks",
    title: "Permission Blocks",
    route: "/permission-blocks",
    description:
      "Rows from permission_blocks: reusable scope, effect, condition, and action sets.",
    icon: Boxes,
    queryName: "permissionBlocks",
    tenantFilter: true,
    listQuery: `query PermissionBlocks($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { permissionBlocks(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id tenantId scopeMode objectKind objectType objectId groupId effect conditions actions { id name } createdAt updatedAt } } }`,
    createMutation: `mutation CreatePermissionBlock($input: CreatePermissionBlockInput!) { createPermissionBlock(input: $input) { id tenantId scopeMode objectKind objectType objectId groupId effect createdAt updatedAt } }`,
    deleteMutation: `mutation DeletePermissionBlock($id: ID!) { deletePermissionBlock(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "scopeMode", label: "Scope", priority: "high" },
      { key: "objectKind", label: "Object kind", priority: "medium" },
      { key: "objectType", label: "Object type", priority: "medium" },
      { key: "objectId", label: "Object ID", priority: "low" },
      { key: "groupId", label: "Group", priority: "low" },
      { key: "effect", label: "Effect", priority: "high" },
      { key: "actions", label: "Actions", priority: "high" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "permission-block-demo",
        tenantId: "factory-a",
        scopeMode: "object_type",
        objectKind: "resource",
        objectType: "resource:channel",
        effect: "allow",
        actions: [{ name: "read" }, { name: "publish" }],
      },
    ],
    missing: {
      update:
        "Permission blocks are replaced by creating a new block and relinking roles or direct policies.",
    },
  },
  {
    key: "capability-actions",
    title: "Actions",
    route: "/actions",
    description:
      "Rows from actions: one unique operation name such as read, write, publish, or execute.",
    icon: KeyRound,
    queryName: "actions",
    listQuery: `query Actions($limit: Int = 50, $offset: Int = 0) { actions(limit: $limit, offset: $offset) { total items { id name description createdAt updatedAt } } }`,
    createMutation: `mutation CreateAction($input: CreateActionInput!) { createAction(input: $input) { id name description createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteAction($id: ID!) { deleteAction(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "description", label: "Description", priority: "low" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "action-read",
        name: "read",
        description: "Read / view an object",
      },
    ],
    missing: {
      update: "Action update is not exposed in this table yet.",
    },
  },
  {
    key: "capabilities",
    title: "Action Applicability",
    route: "/actions",
    description:
      "Rows from action_applicability: each action/object-kind/object-type pair stored in Atom.",
    icon: KeyRound,
    queryName: "actionApplicability",
    listQuery: `query ActionApplicability($actionName: String, $objectKind: String, $objectType: String, $limit: Int = 50, $offset: Int = 0) { actionApplicability(actionName: $actionName, objectKind: $objectKind, objectType: $objectType, limit: $limit, offset: $offset) { total items { id actionId actionName objectKind objectType description createdAt } } }`,
    createMutation: `mutation AddActionApplicability($input: AddActionApplicabilityInput!) { addActionApplicability(input: $input) { id actionId actionName objectKind objectType createdAt } }`,
    deleteMutation: `mutation RemoveActionApplicability($input: RemoveActionApplicabilityInput!) { removeActionApplicability(input: $input) }`,
    filters: [
      {
        key: "actionName",
        variable: "actionName",
        label: "action_name",
        type: "text",
        placeholder: "Filter action...",
      },
      {
        key: "objectKind",
        variable: "objectKind",
        label: "object_kind",
        type: "select",
        options: [
          { label: "Entity", value: "entity" },
          { label: "Resource", value: "resource" },
          { label: "Object group", value: "group" },
          { label: "Tenant", value: "tenant" },
          { label: "Role", value: "role" },
          { label: "Policy", value: "policy" },
          { label: "Credential", value: "credential" },
          { label: "Audit log", value: "audit_log" },
          { label: "Signing key", value: "signing_key" },
        ],
      },
      {
        key: "objectType",
        variable: "objectType",
        label: "object_type",
        type: "select",
        options: [
          { label: "Human entity", value: "entity:human" },
          { label: "Device/client entity", value: "entity:device" },
          { label: "Service entity", value: "entity:service" },
          { label: "Workload entity", value: "entity:workload" },
          { label: "Application entity", value: "entity:application" },
          { label: "Channel resource", value: "resource:channel" },
          { label: "Rule resource", value: "resource:rule" },
          { label: "Report resource", value: "resource:report" },
          { label: "Alarm resource", value: "resource:alarm" },
        ],
      },
    ],
    columns: [
      { key: "actionName", label: "Action", priority: "high" },
      { key: "actionId", label: "Action ID", priority: "medium" },
      { key: "objectKind", label: "Object kind", priority: "high" },
      { key: "objectType", label: "Object type", priority: "high" },
      { key: "description", label: "Description", priority: "low" },
      { key: "createdAt", label: "Created", priority: "low" },
    ],
    sampleRows: [
      {
        id: "action-publish:resource:resource-channel",
        actionId: "action-publish",
        actionName: "publish",
        objectKind: "resource",
        objectType: "resource:channel",
        description: "Publish messages",
      },
    ],
    missing: {
      update:
        "Action applicability rows are replaced by deleting and creating rows.",
    },
  },
  {
    key: "action-assignment-rules",
    title: "Assignment Guardrails",
    route: "/actions",
    description:
      "Rows from action_assignment_rules: assignment-time allow and deny guardrails by entity kind, action, and protected object.",
    icon: SlidersHorizontal,
    queryName: "actionAssignmentRules",
    tenantFilter: true,
    listQuery: `query ActionAssignmentRules($tenantId: ID, $entityKind: EntityKind, $actionName: String, $objectKind: String, $decision: ActionAssignmentRuleDecision, $limit: Int = 50, $offset: Int = 0) { actionAssignmentRules(tenantId: $tenantId, entityKind: $entityKind, actionName: $actionName, objectKind: $objectKind, decision: $decision, limit: $limit, offset: $offset) { total items { id tenantId entityKind actionName objectKind objectType decision isAbsolute createdAt } } }`,
    deleteMutation: `mutation DeleteActionAssignmentRule($id: ID!) { deleteActionAssignmentRule(id: $id) }`,
    deleteIdField: "id",
    filters: [
      {
        key: "entityKind",
        variable: "entityKind",
        label: "entity_kind",
        type: "select",
        options: [
          { label: "Human", value: "human" },
          { label: "Device", value: "device" },
          { label: "Service", value: "service" },
          { label: "Workload", value: "workload" },
          { label: "Application", value: "application" },
        ],
      },
      {
        key: "actionName",
        variable: "actionName",
        label: "action_name",
        type: "text",
        placeholder: "Filter action...",
      },
      {
        key: "objectKind",
        variable: "objectKind",
        label: "object_kind",
        type: "select",
        options: [
          { label: "Entity", value: "entity" },
          { label: "Resource", value: "resource" },
          { label: "Object group", value: "group" },
          { label: "Tenant", value: "tenant" },
          { label: "Role", value: "role" },
          { label: "Policy", value: "policy" },
          { label: "Credential", value: "credential" },
          { label: "Audit log", value: "audit_log" },
          { label: "Signing key", value: "signing_key" },
        ],
      },
      {
        key: "decision",
        variable: "decision",
        label: "decision",
        type: "select",
        options: [
          { label: "Allow", value: "allow" },
          { label: "Deny", value: "deny" },
          { label: "Require override", value: "require_override" },
        ],
      },
    ],
    columns: [
      { key: "tenantId", label: "Scope", priority: "medium" },
      { key: "entityKind", label: "Entity kind", priority: "high" },
      { key: "actionName", label: "Action", priority: "high" },
      { key: "objectKind", label: "Object kind", priority: "high" },
      { key: "objectType", label: "Object type", priority: "medium" },
      { key: "decision", label: "Decision", priority: "high" },
      { key: "isAbsolute", label: "Absolute", priority: "medium" },
      { key: "createdAt", label: "Created", priority: "low" },
    ],
    sampleRows: [
      {
        id: "assignment-rule-device-manage-resource",
        entityKind: "device",
        actionName: "manage",
        objectKind: "resource",
        objectType: null,
        decision: "deny",
        isAbsolute: true,
      },
    ],
    missing: {
      update:
        "Assignment guardrail rules are replaced by deleting and creating rows.",
    },
  },
  {
    key: "policies",
    title: "Direct Policies",
    route: "/policies",
    description:
      "Advanced subject-to-permission-block grants. Normal access should prefer role assignments.",
    icon: GitBranch,
    queryName: "directPolicies",
    listQuery: `query DirectPolicies($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { directPolicies(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id tenantId subjectKind subjectId permissionBlockId createdAt } } }`,
    createMutation: `mutation CreateDirectPolicy($input: CreateDirectPolicyInput!) { createDirectPolicy(input: $input) { id tenantId subjectKind subjectId permissionBlockId createdAt } }`,
    deleteMutation: `mutation DeleteDirectPolicy($id: ID!) { deleteDirectPolicy(id: $id) }`,
    deleteIdField: "id",
    tenantFilter: true,
    columns: [
      { key: "tenantId", label: "Tenant", priority: "medium" },
      { key: "subjectKind", label: "Subject kind", priority: "high" },
      { key: "subjectId", label: "Subject", priority: "high" },
      {
        key: "permissionBlockId",
        label: "Permission block",
        priority: "high",
      },
      { key: "createdAt", label: "Created", priority: "low" },
    ],
    sampleRows: [
      {
        id: "policy-demo",
        subjectKind: "group",
        subjectId: "group-id",
        permissionBlockId: "permission-block-id",
      },
    ],
    missing: {},
  },
];

export const secondaryResources: CrudResource[] = [
  {
    key: "audit",
    title: "Audit Logs",
    route: "/audit",
    description: "Immutable identity and authorization activity.",
    icon: ScrollText,
    queryName: "auditLogs",
    columns: [
      { key: "event", label: "Event", priority: "high" },
      { key: "outcome", label: "Outcome", priority: "high" },
      { key: "createdAt", label: "Time", priority: "medium" },
    ],
    sampleRows: [
      {
        id: "audit-demo",
        event: "authz.check",
        outcome: "allow",
        createdAt: "recently",
      },
    ],
    missing: {
      create: "Audit logs are system-written.",
      update: "Audit logs are immutable.",
      delete: "Audit logs are immutable.",
    },
  },
  {
    key: "authorization-checks",
    title: "Authorization Checks",
    route: "/authz",
    description: "Online PDP checks and explain/debug output.",
    icon: SlidersHorizontal,
    queryName: "authzCheck",
    columns: [
      { key: "subject", label: "Subject", priority: "high" },
      { key: "action", label: "Action", priority: "high" },
      { key: "result", label: "Result", priority: "high" },
    ],
    sampleRows: [
      {
        id: "check-demo",
        subject: "sensor-gateway-01",
        action: "publish",
        result: "allow",
      },
    ],
    missing: {
      update: "Authorization checks are evaluations, not persistent records.",
      delete: "Authorization checks are evaluations, not persistent records.",
    },
  },
  {
    key: "relationships",
    title: "Relationships",
    route: "/entities",
    description:
      "Ownerships, group memberships, role actions, and policy inheritance traces.",
    icon: Network,
    queryName: "ownedEntities",
    columns: [
      { key: "source", label: "Source", priority: "high" },
      { key: "relation", label: "Relation", priority: "high" },
      { key: "target", label: "Target", priority: "high" },
    ],
    sampleRows: [
      {
        id: "rel-demo",
        source: "factory-admin",
        relation: "owns",
        target: "gateway-01",
      },
    ],
    missing: {
      read: "A consolidated relationship graph is not available yet.",
    },
  },
  {
    key: "profile-versions",
    title: "Profile Versions",
    route: "/profiles",
    description:
      "JSON Schema and UI schema revisions for profile-driven forms.",
    icon: Boxes,
    queryName: "profileVersions",
    columns: [
      { key: "version", label: "Version", priority: "high" },
      { key: "status", label: "Status", priority: "high" },
      { key: "createdAt", label: "Created", priority: "medium" },
    ],
    sampleRows: [
      { id: "profile-v1", version: 1, status: "active", createdAt: "seeded" },
    ],
    missing: {
      update: "Profile version updates are not available yet.",
      delete: "Profile version deletion is not available yet.",
    },
  },
];

export function resourceByKey(key: string) {
  return [...crudResources, ...secondaryResources].find(
    (resource) => resource.key === key,
  );
}

export function requireResource(key: string) {
  const resource = resourceByKey(key);
  if (!resource) {
    throw new Error(`Unknown Atom admin resource: ${key}`);
  }
  return resource;
}
