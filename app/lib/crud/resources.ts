import type { LucideIcon } from "lucide-react";
import {
  Boxes,
  Braces,
  Building2,
  Fingerprint,
  GitBranch,
  KeyRound,
  Layers3,
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
      "Isolation boundaries for tenant-scoped entities, groups, resources, and roles.",
    icon: Building2,
    queryName: "tenants",
    listQuery: `query Tenants($limit: Int = 50, $offset: Int = 0) { tenants(limit: $limit, offset: $offset) { total items { id name route tags attributes status createdAt updatedAt } } }`,
    createMutation: `mutation CreateTenant($input: CreateTenantInput!) { createTenant(input: $input) { id name route tags status createdAt updatedAt } }`,
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "route", label: "Route", priority: "medium" },
      { key: "tags", label: "Tags", priority: "medium" },
      { key: "status", label: "Status", priority: "high" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      { id: "global", name: "Global", route: "-", status: "active" },
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
    listQuery: `query Entities($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { entities(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id kind profileId profileVersionId name tenantId attributes status createdAt updatedAt } } }`,
    createMutation: `mutation CreateEntity($input: CreateEntityInput!) { createEntity(input: $input) { id kind profileId profileVersionId name tenantId status createdAt updatedAt } }`,
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "kind", label: "Kind", priority: "high" },
      { key: "profileId", label: "Profile", priority: "medium" },
      { key: "status", label: "Status", priority: "high" },
      { key: "tenantId", label: "Scope", priority: "medium" },
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
    listQuery: `query Profiles($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { profiles(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id objectKind kind key displayName status createdAt updatedAt } } }`,
    createMutation: `mutation CreateProfile($input: CreateProfileInput!) { createProfile(input: $input) { id objectKind kind key displayName status createdAt updatedAt } }`,
    columns: [
      { key: "displayName", label: "Display name", priority: "high" },
      { key: "objectKind", label: "Object", priority: "medium" },
      { key: "kind", label: "Kind", priority: "medium" },
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
    description: "Named tenant-scoped collections used as policy subjects.",
    icon: Users,
    queryName: "groups",
    tenantFilter: true,
    listQuery: `query Groups($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { groups(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id name tenantId description createdAt updatedAt } } }`,
    createMutation: `mutation CreateGroup($input: CreateGroupInput!) { createGroup(input: $input) { id name tenantId description createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteGroup($id: ID!) { deleteGroup(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "tenantId", label: "Scope", priority: "medium" },
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
    listQuery: `query Resources($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { resources(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id kind name tenantId ownerId attributes createdAt updatedAt } } }`,
    createMutation: `mutation CreateResource($input: CreateResourceInput!) { createResource(input: $input) { id kind name tenantId ownerId createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteResource($id: ID!) { deleteResource(id: $id) }`,
    deleteIdField: "id",
    formAttributes: true,
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "kind", label: "Kind", priority: "high" },
      { key: "tenantId", label: "Scope", priority: "medium" },
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
      "Tenant-scoped bundles of capabilities assigned through policies.",
    icon: ShieldCheck,
    queryName: "roles",
    tenantFilter: true,
    listQuery: `query Roles($tenantId: ID, $limit: Int = 50, $offset: Int = 0) { roles(tenantId: $tenantId, limit: $limit, offset: $offset) { total items { id name tenantId description createdAt updatedAt } } }`,
    createMutation: `mutation CreateRole($input: CreateRoleInput!) { createRole(input: $input) { id name tenantId description createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteRole($id: ID!) { deleteRole(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "tenantId", label: "Scope", priority: "medium" },
      { key: "description", label: "Description", priority: "low" },
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
    key: "capabilities",
    title: "Capabilities",
    route: "/capabilities",
    description:
      "Atomic actions such as read, write, publish, subscribe, execute, and manage.",
    icon: KeyRound,
    queryName: "capabilities",
    listQuery: `query Capabilities($limit: Int = 50, $offset: Int = 0) { capabilities(limit: $limit, offset: $offset) { total items { id name resourceKind description createdAt updatedAt } } }`,
    createMutation: `mutation CreateCapability($input: CreateCapabilityInput!) { createCapability(input: $input) { id name resourceKind description createdAt updatedAt } }`,
    deleteMutation: `mutation DeleteCapability($id: ID!) { deleteCapability(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "name", label: "Name", priority: "high" },
      { key: "resourceKind", label: "Resource kind", priority: "medium" },
      { key: "description", label: "Description", priority: "low" },
      { key: "createdAt", label: "Created", priority: "low" },
      { key: "updatedAt", label: "Updated", priority: "low" },
    ],
    sampleRows: [
      {
        id: "cap-publish",
        name: "publish",
        resourceKind: "channel",
        description: "Publish messages",
      },
    ],
    missing: {},
  },
  {
    key: "policies",
    title: "Policy Bindings",
    route: "/policies",
    description:
      "Allow and deny bindings across RBAC grants, ABAC conditions, and authorization scopes.",
    icon: GitBranch,
    queryName: "policies",
    listQuery: `query Policies($limit: Int = 50, $offset: Int = 0) { policies(limit: $limit, offset: $offset) { total items { id subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt } } }`,
    createMutation: `mutation CreatePolicy($input: CreatePolicyInput!) { createPolicy(input: $input) { id subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt } }`,
    deleteMutation: `mutation DeletePolicy($id: ID!) { deletePolicy(id: $id) }`,
    deleteIdField: "id",
    columns: [
      { key: "effect", label: "Effect", priority: "high" },
      { key: "subjectKind", label: "Subject kind", priority: "high" },
      { key: "subjectId", label: "Subject ID", priority: "high" },
      { key: "grantKind", label: "Grant kind", priority: "medium" },
      { key: "grantId", label: "Grant ID", priority: "medium" },
      { key: "scopeKind", label: "Scope kind", priority: "high" },
      { key: "scopeRef", label: "Scope ref", priority: "medium" },
      { key: "createdAt", label: "Created", priority: "low" },
    ],
    sampleRows: [
      {
        id: "policy-demo",
        effect: "allow",
        subjectKind: "group",
        subjectId: "group-id",
        grantKind: "role",
        grantId: "role-id",
        scopeKind: "object_type",
        scopeRef: "channel",
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
      "Ownerships, group memberships, role capabilities, and policy inheritance traces.",
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
    key: "role-capabilities",
    title: "Role Capabilities",
    route: "/roles",
    description: "Capability mappings bundled into roles.",
    icon: Layers3,
    queryName: "roleCapabilities",
    columns: [
      { key: "role", label: "Role", priority: "high" },
      { key: "capability", label: "Capability", priority: "high" },
      { key: "resourceKind", label: "Resource", priority: "medium" },
    ],
    sampleRows: [
      {
        id: "role-cap-demo",
        role: "publisher",
        capability: "publish",
        resourceKind: "channel",
      },
    ],
    missing: {},
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
