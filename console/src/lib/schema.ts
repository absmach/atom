export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type LoginResult = {
  token: string;
  entityId: string;
  sessionId: string;
  expiresAt: string;
  emailVerified?: boolean | null;
  verificationRequired?: boolean;
};

export type SignupResult = {
  entity_id: string;
  email: string;
  verification_required: boolean;
};

export type PublicAuthConfig = {
  signup_enabled: boolean;
  oauth_providers: string[];
  email_verification_required: boolean;
  dev_allow_unverified_email_login: boolean;
};

export type GraphqlError = {
  message: string;
};

export type GraphqlEnvelope<T> = {
  data?: T;
  errors?: GraphqlError[];
};

export type ListResult<T> = {
  items: T[];
  total: number;
};

export type Tenant = {
  id: string;
  name: string;
  route: string | null;
  status: string;
  tags: string[];
  attributes: JsonValue;
  createdAt: string;
  updatedAt: string;
};

export type Profile = {
  id: string;
  tenantId: string | null;
  objectKind: string;
  kind: string;
  key: string;
  displayName: string;
  description: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
};

export type ProfileVersion = {
  id: string;
  profileId: string;
  version: number;
  jsonSchema: JsonValue;
  uiSchema: JsonValue;
  status: string;
  createdAt: string;
};

export type Entity = {
  id: string;
  kind: string;
  profileId: string | null;
  profileVersionId: string | null;
  name: string;
  tenantId: string | null;
  status: string;
  attributes: JsonValue;
  createdAt: string;
  updatedAt: string;
};

export type Resource = {
  id: string;
  kind: string;
  name: string | null;
  tenantId: string | null;
  ownerId: string | null;
  attributes: JsonValue;
  createdAt: string;
  updatedAt: string;
};

export type ApiEndpoint = {
  id: string;
  tenantId: string | null;
  key: string;
  name: string;
  description: string | null;
  method: string;
  path: string;
  operationKind: "query" | "mutation";
  graphql: string;
  authMode: string;
  serviceEntityId: string | null;
  variablesMapping: JsonValue;
  requestSchema: JsonValue;
  responseMapping: JsonValue;
  status: "draft" | "active" | "disabled";
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ApiEndpointExecution = {
  id: string;
  endpointId: string | null;
  callerEntityId: string | null;
  status: "success" | "error" | "denied";
  requestSummary: JsonValue;
  responseSummary: JsonValue;
  error: string | null;
  createdAt: string;
};

export type Credential = {
  id: string;
  entityId: string | null;
  kind: string;
  identifier: string | null;
  status: string;
  expiresAt: string | null;
  createdAt: string;
};

export type ApiKeyResponse = {
  credentialId: string;
  key: string;
  expiresAt: string | null;
};

export type Role = {
  id: string;
  name: string;
  tenantId: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
};

export type Capability = {
  id: string;
  name: string;
  resourceKind: string | null;
  description: string | null;
};

export type Group = {
  id: string;
  name: string;
  tenantId: string | null;
  description: string | null;
  createdAt: string;
  updatedAt: string;
};

export type PolicyBinding = {
  id: string;
  tenantId: string | null;
  subjectKind: "entity" | "group";
  subjectId: string;
  grantKind: "capability" | "role";
  grantId: string;
  scopeKind: "platform" | "tenant" | "object_kind" | "object_type" | "object";
  scopeRef: string | null;
  effect: "allow" | "deny";
  conditions: JsonValue;
  createdAt: string;
};

export type AuthzResponse = {
  allowed: boolean;
  reason: string;
  details?: JsonValue | null;
};

export type AuthzExplainResponse = AuthzResponse & {
  subject?: JsonValue | null;
  resource?: JsonValue | null;
  capability?: JsonValue | null;
  matchedBinding?: JsonValue | null;
  evaluatedBindings: JsonValue;
};
