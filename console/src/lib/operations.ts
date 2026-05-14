import type { ApiEndpoint, JsonObject, JsonValue } from "./schema";

export const HEALTH_QUERY = `query ConsoleHealth {
  health
}`;

export const LOGIN_MUTATION = `mutation ConsoleLogin($input: LoginInput!) {
  login(input: $input) {
    token
    entityId
    sessionId
    expiresAt
    emailVerified
    verificationRequired
  }
}`;

export const LOGOUT_MUTATION = `mutation ConsoleLogout {
  logout
}`;

export const TENANTS_QUERY = `query ConsoleTenants($name: String, $route: String, $status: TenantStatus, $limit: Int, $offset: Int) {
  tenants(name: $name, route: $route, status: $status, limit: $limit, offset: $offset) {
    items { id name route status tags attributes createdAt updatedAt }
    total
  }
}`;

export const CREATE_TENANT = `mutation ConsoleCreateTenant($input: CreateTenantInput!) {
  createTenant(input: $input) { id name route status tags attributes createdAt updatedAt }
}`;

export const UPDATE_TENANT = `mutation ConsoleUpdateTenant($id: ID!, $input: UpdateTenantInput!) {
  updateTenant(id: $id, input: $input) { id name route status tags attributes createdAt updatedAt }
}`;

export const ENABLE_TENANT = `mutation ConsoleEnableTenant($id: ID!) {
  enableTenant(id: $id) { id name status updatedAt }
}`;

export const DISABLE_TENANT = `mutation ConsoleDisableTenant($id: ID!) {
  disableTenant(id: $id) { id name status updatedAt }
}`;

export const FREEZE_TENANT = `mutation ConsoleFreezeTenant($id: ID!) {
  freezeTenant(id: $id) { id name status updatedAt }
}`;

export const PROFILES_QUERY = `query ConsoleProfiles($objectKind: String, $kind: String, $tenantId: ID, $status: String, $limit: Int, $offset: Int) {
  profiles(objectKind: $objectKind, kind: $kind, tenantId: $tenantId, status: $status, limit: $limit, offset: $offset) {
    items { id tenantId objectKind kind key displayName description status createdAt updatedAt }
    total
  }
}`;

export const PROFILE_VERSIONS_QUERY = `query ConsoleProfileVersions($profileId: ID!) {
  profileVersions(profileId: $profileId) {
    id profileId version jsonSchema uiSchema status createdAt
  }
}`;

export const CREATE_PROFILE = `mutation ConsoleCreateProfile($input: CreateProfileInput!) {
  createProfile(input: $input) { id tenantId objectKind kind key displayName description status createdAt updatedAt }
}`;

export const UPDATE_PROFILE = `mutation ConsoleUpdateProfile($id: ID!, $input: UpdateProfileInput!) {
  updateProfile(id: $id, input: $input) { id tenantId objectKind kind key displayName description status createdAt updatedAt }
}`;

export const CREATE_PROFILE_VERSION = `mutation ConsoleCreateProfileVersion($profileId: ID!, $input: CreateProfileVersionInput!) {
  createProfileVersion(profileId: $profileId, input: $input) { id profileId version jsonSchema uiSchema status createdAt }
}`;

export const ENTITIES_QUERY = `query ConsoleEntities($kind: EntityKind, $profileId: ID, $tenantId: ID, $status: EntityStatus, $limit: Int, $offset: Int) {
  entities(kind: $kind, profileId: $profileId, tenantId: $tenantId, status: $status, limit: $limit, offset: $offset) {
    items { id kind profileId profileVersionId name tenantId status attributes createdAt updatedAt }
    total
  }
}`;

export const CREATE_ENTITY = `mutation ConsoleCreateEntity($input: CreateEntityInput!) {
  createEntity(input: $input) { id kind profileId profileVersionId name tenantId status attributes createdAt updatedAt }
}`;

export const CREDENTIALS_QUERY = `query ConsoleCredentials($entityId: ID!) {
  credentials(entityId: $entityId) {
    items { id entityId kind identifier status expiresAt createdAt }
    total
  }
}`;

export const CREATE_PASSWORD = `mutation ConsoleCreatePassword($entityId: ID!, $password: String!) {
  createPassword(entityId: $entityId, password: $password)
}`;

export const CREATE_API_KEY = `mutation ConsoleCreateApiKey($entityId: ID!, $input: CreateApiKeyInput!) {
  createApiKey(entityId: $entityId, input: $input) { credentialId key expiresAt }
}`;

export const REVOKE_CREDENTIAL = `mutation ConsoleRevokeCredential($entityId: ID!, $credentialId: ID!) {
  revokeCredential(entityId: $entityId, credentialId: $credentialId)
}`;

export const RESOURCES_QUERY = `query ConsoleResources($kind: String, $tenantId: ID, $limit: Int, $offset: Int) {
  resources(kind: $kind, tenantId: $tenantId, limit: $limit, offset: $offset) {
    items { id kind name tenantId ownerId attributes createdAt updatedAt }
    total
  }
}`;

export const CREATE_RESOURCE = `mutation ConsoleCreateResource($input: CreateResourceInput!) {
  createResource(input: $input) { id kind name tenantId ownerId attributes createdAt updatedAt }
}`;

export const UPDATE_RESOURCE = `mutation ConsoleUpdateResource($id: ID!, $input: UpdateResourceInput!) {
  updateResource(id: $id, input: $input) { id kind name tenantId ownerId attributes createdAt updatedAt }
}`;

export const DELETE_RESOURCE = `mutation ConsoleDeleteResource($id: ID!) {
  deleteResource(id: $id)
}`;

export const ENDPOINTS_QUERY = `query ConsoleApiEndpoints($tenantId: ID, $status: String, $limit: Int, $offset: Int) {
  apiEndpoints(tenantId: $tenantId, status: $status, limit: $limit, offset: $offset) {
    items {
      id tenantId key name description method path operationKind graphql authMode serviceEntityId variablesMapping requestSchema responseMapping status createdBy updatedBy createdAt updatedAt
    }
    total
  }
}`;

export const CREATE_ENDPOINT = `mutation ConsoleCreateEndpoint($input: CreateApiEndpointInput!) {
  createApiEndpoint(input: $input) {
    id tenantId key name description method path operationKind graphql authMode serviceEntityId variablesMapping requestSchema responseMapping status createdBy updatedBy createdAt updatedAt
  }
}`;

export const UPDATE_ENDPOINT = `mutation ConsoleUpdateEndpoint($id: ID!, $input: UpdateApiEndpointInput!) {
  updateApiEndpoint(id: $id, input: $input) {
    id tenantId key name description method path operationKind graphql authMode serviceEntityId variablesMapping requestSchema responseMapping status createdBy updatedBy createdAt updatedAt
  }
}`;

export const ENABLE_ENDPOINT = `mutation ConsoleEnableEndpoint($id: ID!) {
  enableApiEndpoint(id: $id) { id status updatedAt }
}`;

export const DISABLE_ENDPOINT = `mutation ConsoleDisableEndpoint($id: ID!) {
  disableApiEndpoint(id: $id) { id status updatedAt }
}`;

export const ENDPOINT_EXECUTIONS_QUERY = `query ConsoleApiEndpointExecutions($endpointId: ID!, $limit: Int, $offset: Int) {
  apiEndpointExecutions(endpointId: $endpointId, limit: $limit, offset: $offset) {
    items { id endpointId callerEntityId status requestSummary responseSummary error createdAt }
    total
  }
}`;

export const ROLES_QUERY = `query ConsoleRoles($tenantId: ID, $limit: Int, $offset: Int) {
  roles(tenantId: $tenantId, limit: $limit, offset: $offset) {
    items { id name tenantId description createdAt updatedAt }
    total
  }
}`;

export const CAPABILITIES_QUERY = `query ConsoleCapabilities($resourceKind: String, $tenantId: ID) {
  capabilities(resourceKind: $resourceKind, tenantId: $tenantId) {
    items { id name resourceKind description }
    total
  }
}`;

export const GROUPS_QUERY = `query ConsoleGroups($tenantId: ID, $limit: Int, $offset: Int) {
  groups(tenantId: $tenantId, limit: $limit, offset: $offset) {
    items { id name tenantId description createdAt updatedAt }
    total
  }
}`;

export const GROUP_MEMBERS_QUERY = `query ConsoleGroupMembers($groupId: ID!) {
  groupMembers(groupId: $groupId) {
    id kind profileId profileVersionId name tenantId status attributes createdAt updatedAt
  }
}`;

export const CREATE_GROUP = `mutation ConsoleCreateGroup($input: CreateGroupInput!) {
  createGroup(input: $input) { id name tenantId description createdAt updatedAt }
}`;

export const DELETE_GROUP = `mutation ConsoleDeleteGroup($id: ID!) {
  deleteGroup(id: $id)
}`;

export const ADD_GROUP_MEMBER = `mutation ConsoleAddGroupMember($groupId: ID!, $entityId: ID!) {
  addGroupMember(groupId: $groupId, entityId: $entityId)
}`;

export const REMOVE_GROUP_MEMBER = `mutation ConsoleRemoveGroupMember($groupId: ID!, $entityId: ID!) {
  removeGroupMember(groupId: $groupId, entityId: $entityId)
}`;

export const POLICIES_QUERY = `query ConsolePolicies($tenantId: ID, $subjectId: ID, $subjectKind: SubjectKind, $limit: Int, $offset: Int) {
  policies(tenantId: $tenantId, subjectId: $subjectId, subjectKind: $subjectKind, limit: $limit, offset: $offset) {
    items { id tenantId subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt }
    total
  }
}`;

export const CREATE_POLICY = `mutation ConsoleCreatePolicy($input: CreatePolicyInput!) {
  createPolicy(input: $input) { id tenantId subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt }
}`;

export const AUTHZ_CHECK = `mutation ConsoleAuthzCheck($input: AuthzCheckInput!) {
  authzCheck(input: $input) { allowed reason details }
}`;

export const AUTHZ_EXPLAIN = `mutation ConsoleAuthzExplain($input: AuthzCheckInput!) {
  authzExplain(input: $input) { allowed reason subject resource capability matchedBinding evaluatedBindings }
}`;

export const AUTHZ_BULK_CHECK = `mutation ConsoleAuthzBulkCheck($input: [AuthzCheckInput!]!) {
  authzBulkCheck(input: $input) { allowed reason details }
}`;

export const INTROSPECTION_QUERY = `query ConsoleIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name description type { ...TypeRef } defaultValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
      }
      inputFields { name description type { ...TypeRef } defaultValue }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
    }
  }
}
fragment TypeRef on __Type {
  kind
  name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}`;

export function graphQlCurl(query: string, variables: JsonObject): string {
  return [
    'curl -X POST "$ATOM_URL/graphql"',
    '  -H "Authorization: Bearer $TOKEN"',
    '  -H "Content-Type: application/json"',
    `  --data '${JSON.stringify({ query, variables }, null, 2)}'`,
  ].join(" \\\n");
}

export function graphQlFetch(query: string, variables: JsonObject): string {
  return `const response = await fetch("/graphql", {
  method: "POST",
  headers: {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json"
  },
  body: JSON.stringify(${JSON.stringify({ query, variables }, null, 2)})
});

const result = await response.json();`;
}

export function endpointCurl(endpoint: Pick<ApiEndpoint, "method" | "path">, body: JsonValue): string {
  const lines = [
    `curl -X ${endpoint.method} "${endpoint.path}"`,
    '  -H "Authorization: Bearer $TOKEN"',
  ];
  if (!["GET", "DELETE"].includes(endpoint.method)) {
    lines.push('  -H "Content-Type: application/json"', `  --data '${JSON.stringify(body, null, 2)}'`);
  }
  return lines.join(" \\\n");
}

export function endpointFetch(endpoint: Pick<ApiEndpoint, "method" | "path">, body: JsonValue): string {
  const bodyLine = ["GET", "DELETE"].includes(endpoint.method)
    ? ""
    : `,\n  body: JSON.stringify(${JSON.stringify(body, null, 2)})`;
  return `const response = await fetch("${endpoint.path}", {
  method: "${endpoint.method}",
  headers: {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json"
  }${bodyLine}
});

const result = await response.json();`;
}
