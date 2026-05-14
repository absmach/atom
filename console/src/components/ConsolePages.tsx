import {
  Database,
  FileCode2,
  KeyRound,
  Network,
  Play,
  Plus,
  Save,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { type ReactNode, type SyntheticEvent, useEffect, useMemo, useState } from "react";
import { clearToken, getToken } from "../lib/auth";
import { customEndpoint, gql, rawGql } from "../lib/graphql";
import {
  compactNullable,
  isJsonObject,
  jsonString,
  parseJson,
  parseJsonObject,
  tagsFromText,
  textFromTags,
} from "../lib/json";
import {
  AUTHZ_BULK_CHECK,
  AUTHZ_CHECK,
  AUTHZ_EXPLAIN,
  CAPABILITIES_QUERY,
  ADD_GROUP_MEMBER,
  CREATE_API_KEY,
  CREATE_ENDPOINT,
  CREATE_ENTITY,
  CREATE_GROUP,
  CREATE_PASSWORD,
  CREATE_POLICY,
  CREATE_PROFILE,
  CREATE_PROFILE_VERSION,
  CREATE_RESOURCE,
  CREATE_TENANT,
  CREDENTIALS_QUERY,
  DELETE_GROUP,
  DELETE_RESOURCE,
  DISABLE_ENDPOINT,
  DISABLE_TENANT,
  ENABLE_ENDPOINT,
  ENABLE_TENANT,
  ENDPOINTS_QUERY,
  ENDPOINT_EXECUTIONS_QUERY,
  ENTITIES_QUERY,
  FREEZE_TENANT,
  GROUP_MEMBERS_QUERY,
  GROUPS_QUERY,
  HEALTH_QUERY,
  INTROSPECTION_QUERY,
  POLICIES_QUERY,
  PROFILE_VERSIONS_QUERY,
  PROFILES_QUERY,
  REVOKE_CREDENTIAL,
  RESOURCES_QUERY,
  ROLES_QUERY,
  REMOVE_GROUP_MEMBER,
  TENANTS_QUERY,
  UPDATE_ENDPOINT,
  UPDATE_PROFILE,
  UPDATE_RESOURCE,
  UPDATE_TENANT,
  endpointCurl,
  endpointFetch,
  graphQlCurl,
  graphQlFetch,
} from "../lib/operations";
import { CONSOLE_BASE, TASK_ROUTES } from "../lib/routes";
import type {
  ApiEndpoint,
  ApiEndpointExecution,
  ApiKeyResponse,
  AuthzExplainResponse,
  AuthzResponse,
  Capability,
  Credential,
  Entity,
  GraphqlEnvelope,
  Group,
  JsonObject,
  JsonValue,
  ListResult,
  PolicyBinding,
  Profile,
  ProfileVersion,
  Resource,
  Role,
  Tenant,
} from "../lib/schema";
import { BackendStatus } from "./BackendStatus";
import {
  CopyButton,
  EmptyState,
  ErrorNotice,
  JsonTextarea,
  Loading,
  PageHeader,
  Panel,
  PreviewPanel,
  RefreshButton,
  ResultPanel,
  StatusBadge,
  preventDefault,
} from "./ConsolePrimitives";
import { JsonSchemaForm } from "./JsonSchemaForm";
import { LoginPanel } from "./LoginPanel";

type LoadState = "idle" | "loading" | "loaded";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

function enumOrNull(value: string): string | null {
  return value === "" ? null : value;
}

function safeVariables(build: () => JsonObject): JsonObject {
  try {
    return build();
  } catch (caught) {
    return { inputError: errorMessage(caught) };
  }
}

function submit(handler: () => Promise<void> | void) {
  return (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    void handler();
  };
}

function useTokenVersion(): number {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const bump = () => setVersion((current) => current + 1);
    window.addEventListener("atom-console-auth", bump);
    return () => window.removeEventListener("atom-console-auth", bump);
  }, []);
  return version;
}

function MiniTable<T>({
  items,
  empty,
  children,
}: {
  items: T[];
  empty: string;
  children: (item: T) => ReactNode;
}) {
  if (!items.length) {
    return <EmptyState>{empty}</EmptyState>;
  }
  return <div className="record-list">{items.map(children)}</div>;
}

function JsonDetails({ title, value }: { title: string; value: JsonValue }) {
  return (
    <details>
      <summary>{title}</summary>
      <pre>{jsonString(value)}</pre>
    </details>
  );
}

export function DashboardPage() {
  const tokenVersion = useTokenVersion();
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [executions, setExecutions] = useState<Record<string, ApiEndpointExecution | undefined>>({});
  const [error, setError] = useState<string | null>(null);
  const [state, setState] = useState<LoadState>("idle");

  async function load() {
    if (!getToken()) {
      setState("loaded");
      return;
    }
    setState("loading");
    setError(null);
    try {
      const endpointData = await gql<{ apiEndpoints: ListResult<ApiEndpoint> }>(ENDPOINTS_QUERY, {
        limit: 5,
        offset: 0,
      });
      setEndpoints(endpointData.apiEndpoints.items);
      const latest = await Promise.all(
        endpointData.apiEndpoints.items.map(async (endpoint) => {
          try {
            const data = await gql<{ apiEndpointExecutions: ListResult<ApiEndpointExecution> }>(
              ENDPOINT_EXECUTIONS_QUERY,
              { endpointId: endpoint.id, limit: 1, offset: 0 },
            );
            return [endpoint.id, data.apiEndpointExecutions.items[0]] as const;
          } catch {
            return [endpoint.id, undefined] as const;
          }
        }),
      );
      setExecutions(Object.fromEntries(latest));
      setState("loaded");
    } catch (caught) {
      setError(errorMessage(caught));
      setState("loaded");
    }
  }

  useEffect(() => {
    void load();
  }, [tokenVersion]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Dashboard" title="Atom API Builder">
        <BackendStatus />
      </PageHeader>
      <ErrorNotice message={error} />
      <div className="dashboard-grid">
        <Panel title="Workflows" eyebrow="Quick actions" className="span-2">
          <div className="task-grid">
            {TASK_ROUTES.map((route, index) => (
              <a className="task-link" href={route.href} key={route.href}>
                {index < 2 ? <FileCode2 size={18} /> : index < 6 ? <Database size={18} /> : <ShieldCheck size={18} />}
                <span>{route.label}</span>
              </a>
            ))}
          </div>
        </Panel>
        <LoginPanel />
        <Panel title="Recent Endpoints" eyebrow="Build" actions={<RefreshButton onClick={load} busy={state === "loading"} />}>
          {state === "loading" ? <Loading /> : null}
          <MiniTable items={endpoints} empty="No recent endpoints loaded.">
            {(endpoint) => (
              <a className="record-row" href={`${CONSOLE_BASE}/endpoints`} key={endpoint.id}>
                <div>
                  <strong>
                    {endpoint.method} {endpoint.path}
                  </strong>
                  <small>{endpoint.name}</small>
                </div>
                <StatusBadge value={endpoint.status} />
              </a>
            )}
          </MiniTable>
        </Panel>
        <Panel title="Recent Executions" eyebrow="Observe">
          <MiniTable items={endpoints.filter((endpoint) => executions[endpoint.id])} empty="No endpoint executions loaded.">
            {(endpoint) => {
              const execution = executions[endpoint.id];
              return (
                <div className="record-row" key={endpoint.id}>
                  <div>
                    <strong>{endpoint.path}</strong>
                    <small>{execution?.createdAt}</small>
                  </div>
                  <StatusBadge value={execution?.status} />
                </div>
              );
            }}
          </MiniTable>
        </Panel>
      </div>
    </div>
  );
}

type EndpointForm = {
  tenantId: string;
  key: string;
  name: string;
  description: string;
  method: string;
  path: string;
  operationKind: "query" | "mutation";
  graphql: string;
  authMode: string;
  serviceEntityId: string;
  variablesMapping: string;
  requestSchema: string;
  responseMapping: string;
  status: "draft" | "active" | "disabled";
};

type EndpointPreset = {
  key: string;
  label: string;
  description: string;
  operationKind: EndpointForm["operationKind"];
  graphql: string;
  variablesMapping: JsonObject;
  requestSchema: JsonObject;
  responseMapping: JsonObject;
  sampleBody: JsonObject;
};

const ENDPOINT_PRESETS: EndpointPreset[] = [
  {
    key: "health",
    label: "Health check",
    description: "Read Atom health through a custom endpoint.",
    operationKind: "query",
    graphql: "query EndpointHealth { health }",
    variablesMapping: {},
    requestSchema: {},
    responseMapping: { data: "$.health" },
    sampleBody: {},
  },
  {
    key: "create_tenant",
    label: "Create tenant",
    description: "Create a tenant from a compact request body.",
    operationKind: "mutation",
    graphql:
      "mutation CreateTenant($input: CreateTenantInput!) {\n  createTenant(input: $input) { id name route status tags attributes createdAt updatedAt }\n}",
    variablesMapping: { input: "$body" },
    requestSchema: {
      type: "object",
      required: ["name"],
      properties: {
        name: { type: "string" },
        route: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
        attributes: { type: "object" },
      },
    },
    responseMapping: { tenant: "$.createTenant" },
    sampleBody: { name: "factory-a", route: "factory-a" },
  },
  {
    key: "create_entity",
    label: "Create entity",
    description: "Create a human, device, service, workload, or application entity.",
    operationKind: "mutation",
    graphql:
      "mutation CreateEntity($input: CreateEntityInput!) {\n  createEntity(input: $input) { id kind name tenantId status attributes createdAt updatedAt }\n}",
    variablesMapping: { input: "$body" },
    requestSchema: {
      type: "object",
      required: ["name", "kind"],
      properties: {
        tenantId: { type: "string" },
        kind: { type: "string" },
        name: { type: "string" },
        attributes: { type: "object" },
      },
    },
    responseMapping: { entity: "$.createEntity" },
    sampleBody: { kind: "device", name: "device-01", attributes: {} },
  },
  {
    key: "create_resource",
    label: "Create resource",
    description: "Create a protected Atom resource such as a channel.",
    operationKind: "mutation",
    graphql:
      "mutation CreateResource($input: CreateResourceInput!) {\n  createResource(input: $input) { id kind name tenantId ownerId attributes createdAt updatedAt }\n}",
    variablesMapping: { input: "$body" },
    requestSchema: {
      type: "object",
      required: ["kind"],
      properties: {
        tenantId: { type: "string" },
        kind: { type: "string" },
        name: { type: "string" },
        ownerId: { type: "string" },
        attributes: { type: "object" },
      },
    },
    responseMapping: { resource: "$.createResource" },
    sampleBody: { kind: "channel", name: "telemetry" },
  },
  {
    key: "create_policy",
    label: "Create policy",
    description: "Bind a subject to a capability or role over a scope.",
    operationKind: "mutation",
    graphql:
      "mutation CreatePolicy($input: CreatePolicyInput!) {\n  createPolicy(input: $input) { id tenantId subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt }\n}",
    variablesMapping: { input: "$body" },
    requestSchema: {
      type: "object",
      required: ["subjectKind", "subjectId", "grantKind", "grantId", "scopeKind", "effect"],
      properties: {
        tenantId: { type: "string" },
        subjectKind: { type: "string" },
        subjectId: { type: "string" },
        grantKind: { type: "string" },
        grantId: { type: "string" },
        scopeKind: { type: "string" },
        scopeRef: { type: "string" },
        effect: { type: "string" },
        conditions: { type: "object" },
      },
    },
    responseMapping: { policy: "$.createPolicy" },
    sampleBody: { subjectKind: "entity", grantKind: "capability", scopeKind: "object", effect: "allow" },
  },
  {
    key: "authz_check",
    label: "Authorization check",
    description: "Run an authz decision for an entity/action/resource tuple.",
    operationKind: "mutation",
    graphql:
      "mutation AuthzCheck($input: AuthzCheckInput!) {\n  authzCheck(input: $input) { allowed reason details }\n}",
    variablesMapping: { input: "$body" },
    requestSchema: {
      type: "object",
      required: ["entityId", "resourceId", "action"],
      properties: {
        entityId: { type: "string" },
        resourceId: { type: "string" },
        action: { type: "string" },
        context: { type: "object" },
      },
    },
    responseMapping: { decision: "$.authzCheck" },
    sampleBody: { action: "view", context: {} },
  },
];

function blankEndpointForm(): EndpointForm {
  return {
    tenantId: "",
    key: "",
    name: "",
    description: "",
    method: "POST",
    path: "/api/custom/",
    operationKind: "query",
    graphql: "{ health }",
    authMode: "caller_context",
    serviceEntityId: "",
    variablesMapping: "{}",
    requestSchema: "{}",
    responseMapping: "{}",
    status: "draft",
  };
}

function formFromEndpoint(endpoint: ApiEndpoint): EndpointForm {
  return {
    tenantId: endpoint.tenantId ?? "",
    key: endpoint.key,
    name: endpoint.name,
    description: endpoint.description ?? "",
    method: endpoint.method,
    path: endpoint.path,
    operationKind: endpoint.operationKind,
    graphql: endpoint.graphql,
    authMode: endpoint.authMode,
    serviceEntityId: endpoint.serviceEntityId ?? "",
    variablesMapping: jsonString(endpoint.variablesMapping),
    requestSchema: jsonString(endpoint.requestSchema),
    responseMapping: jsonString(endpoint.responseMapping),
    status: endpoint.status,
  };
}

function endpointInput(form: EndpointForm, status = form.status): JsonObject {
  if (!form.path.startsWith("/api/custom/")) {
    throw new Error("Endpoint path must start with /api/custom/");
  }
  return {
    tenantId: compactNullable(form.tenantId),
    key: form.key.trim(),
    name: form.name.trim(),
    description: compactNullable(form.description),
    method: form.method,
    path: form.path.trim(),
    operationKind: form.operationKind,
    graphql: form.graphql,
    authMode: form.authMode,
    serviceEntityId: compactNullable(form.serviceEntityId),
    variablesMapping: parseJsonObject(form.variablesMapping, "variables mapping"),
    requestSchema: parseJsonObject(form.requestSchema, "request schema"),
    responseMapping: parseJsonObject(form.responseMapping, "response mapping"),
    status,
  };
}

function applyEndpointPreset(form: EndpointForm, preset: EndpointPreset): EndpointForm {
  return {
    ...form,
    key: form.key || preset.key,
    name: form.name || preset.label,
    description: form.description || preset.description,
    operationKind: preset.operationKind,
    graphql: preset.graphql,
    variablesMapping: jsonString(preset.variablesMapping),
    requestSchema: jsonString(preset.requestSchema),
    responseMapping: jsonString(preset.responseMapping),
  };
}

export function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [logs, setLogs] = useState<ApiEndpointExecution[]>([]);
  const [selected, setSelected] = useState<ApiEndpoint | null>(null);
  const [form, setForm] = useState<EndpointForm>(blankEndpointForm());
  const [filter, setFilter] = useState({ tenantId: "", status: "" });
  const [step, setStep] = useState(1);
  const [sampleBody, setSampleBody] = useState("{}");
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      const endpointData = await gql<{ apiEndpoints: ListResult<ApiEndpoint> }>(ENDPOINTS_QUERY, {
        tenantId: compactNullable(filter.tenantId),
        status: enumOrNull(filter.status),
        limit: 100,
        offset: 0,
      });
      setEndpoints(endpointData.apiEndpoints.items);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function save(status = form.status): Promise<ApiEndpoint | null> {
    setBusy(true);
    setError(null);
    try {
      const input = endpointInput(form, status);
      const endpoint = selected
        ? (await gql<{ updateApiEndpoint: ApiEndpoint }>(UPDATE_ENDPOINT, { id: selected.id, input }))
            .updateApiEndpoint
        : (await gql<{ createApiEndpoint: ApiEndpoint }>(CREATE_ENDPOINT, { input })).createApiEndpoint;
      setSelected(endpoint);
      setForm(formFromEndpoint(endpoint));
      setResult(endpoint);
      await load();
      return endpoint;
    } catch (caught) {
      setError(errorMessage(caught));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function publish() {
    const saved = await save("draft");
    if (!saved) {
      return;
    }
    setBusy(true);
    try {
      const data = await gql<{ enableApiEndpoint: Pick<ApiEndpoint, "id" | "status" | "updatedAt"> }>(ENABLE_ENDPOINT, { id: saved.id });
      setResult(data.enableApiEndpoint);
      await load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(endpoint: ApiEndpoint, next: "active" | "disabled") {
    setBusy(true);
    setError(null);
    try {
      await gql(next === "active" ? ENABLE_ENDPOINT : DISABLE_ENDPOINT, { id: endpoint.id });
      await load();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  async function loadLogs(endpointId = selected?.id) {
    if (!endpointId) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const data = await gql<{ apiEndpointExecutions: ListResult<ApiEndpointExecution> }>(ENDPOINT_EXECUTIONS_QUERY, {
        endpointId,
        limit: 20,
        offset: 0,
      });
      setLogs(data.apiEndpointExecutions.items);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  async function testEndpoint() {
    if (!selected || selected.status !== "active") {
      setError("Publish endpoint before running an HTTP test; only active endpoints execute under /api/custom/.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body = parseJson(sampleBody, "sample request body");
      const response = await customEndpoint(selected.method, selected.path, body);
      setResult({ status: response.status, ok: response.ok, body: response.text });
      await loadLogs(selected.id);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  const previewEndpoint = { method: form.method, path: form.path };
  const parsedBody = useMemo(() => {
    try {
      return parseJson(sampleBody, "sample body");
    } catch {
      return {};
    }
  }, [sampleBody]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="API Builder" title="Endpoints">
        <RefreshButton onClick={load} busy={busy} />
      </PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Endpoint List" eyebrow={`${endpoints.length} loaded`}>
          <div className="toolbar-grid">
            <input placeholder="Tenant ID" value={filter.tenantId} onChange={(e) => setFilter({ ...filter, tenantId: e.target.value })} />
            <select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })}>
              <option value="">any</option><option>draft</option><option>active</option><option>disabled</option>
            </select>
            <button className="button secondary" type="button" onClick={() => void load()}>Load</button>
            <button className="button primary" type="button" onClick={() => { setSelected(null); setForm(blankEndpointForm()); setStep(1); }}><Plus size={16} /> New</button>
          </div>
          <MiniTable items={endpoints} empty="No endpoints loaded.">
            {(endpoint) => (
              <div className="record-row vertical" key={endpoint.id}>
                <div className="record-main">
                  <button className="link-button" type="button" onClick={() => { setSelected(endpoint); setForm(formFromEndpoint(endpoint)); setStep(1); void loadLogs(endpoint.id); }}>
                    <strong>{endpoint.method} {endpoint.path}</strong>
                  </button>
                  <small>{endpoint.name} · {endpoint.key}</small>
                </div>
                <div className="button-row">
                  <StatusBadge value={endpoint.status} />
                  <button className="button secondary" type="button" onClick={() => void setStatus(endpoint, "active")}>Enable</button>
                  <button className="button secondary" type="button" onClick={() => void setStatus(endpoint, "disabled")}>Disable</button>
                  <CopyButton value={endpointCurl(endpoint, parsedBody)} label="curl" />
                  <CopyButton value={endpointFetch(endpoint, parsedBody)} label="fetch" />
                </div>
              </div>
            )}
          </MiniTable>
        </Panel>
        <Panel title={selected ? "Edit Endpoint" : "Create Endpoint"} eyebrow={`Step ${step} of 4`}>
          <div className="segmented">
            {[1, 2, 3, 4].map((item) => <button className={step === item ? "active" : ""} type="button" key={item} onClick={() => setStep(item)}>{item}</button>)}
          </div>
          <form className="stack" onSubmit={submit(async () => { await save(); })}>
            {step === 1 ? (
              <div className="stack">
                <label>
                  <span>Preset</span>
                  <select
                    value=""
                    onChange={(event) => {
                      const preset = ENDPOINT_PRESETS.find((item) => item.key === event.target.value);
                      if (preset) {
                        setForm((current) => applyEndpointPreset(current, preset));
                        setSampleBody(jsonString(preset.sampleBody));
                      }
                    }}
                  >
                    <option value="">Choose preset</option>
                    {ENDPOINT_PRESETS.map((preset) => (
                      <option key={preset.key} value={preset.key}>{preset.label}</option>
                    ))}
                  </select>
                </label>
                <label><span>Operation</span><select value={form.operationKind} onChange={(e) => setForm({ ...form, operationKind: e.target.value as EndpointForm["operationKind"] })}><option>query</option><option>mutation</option></select></label>
                <label><span>GraphQL</span><textarea rows={10} spellCheck={false} value={form.graphql} onChange={(e) => setForm({ ...form, graphql: e.target.value })} /></label>
              </div>
            ) : null}
            {step === 2 ? (
              <div className="grid-2 compact">
                <label><span>Method</span><select value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value })}><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select></label>
                <label><span>Path</span><input required value={form.path} onChange={(e) => setForm({ ...form, path: e.target.value })} /></label>
                <label><span>Key</span><input required value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} /></label>
                <label><span>Name</span><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
                <label><span>Auth mode</span><select value={form.authMode} onChange={(e) => setForm({ ...form, authMode: e.target.value })}><option>caller_context</option><option>service_context</option></select></label>
                <label><span>Service entity ID</span><input value={form.serviceEntityId} onChange={(e) => setForm({ ...form, serviceEntityId: e.target.value })} /></label>
                <label><span>Tenant ID</span><input value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value })} /></label>
                <label><span>Description</span><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
              </div>
            ) : null}
            {step === 3 ? (
              <div className="grid-2 compact">
                <JsonTextarea label="variablesMapping" value={form.variablesMapping} onChange={(value) => setForm({ ...form, variablesMapping: value })} />
                <JsonTextarea label="requestSchema" value={form.requestSchema} onChange={(value) => setForm({ ...form, requestSchema: value })} />
                <JsonTextarea label="responseMapping" value={form.responseMapping} onChange={(value) => setForm({ ...form, responseMapping: value })} />
                <div className="notice">
                  <Network size={16} />
                  <span>Sources: $body, $body.x, $query.x, $headers.x, $auth.entityId, $auth.tenantId, $auth.sessionId, or literal strings.</span>
                </div>
              </div>
            ) : null}
            {step === 4 ? (
              <div className="stack">
                <JsonTextarea label="Sample request body" value={sampleBody} onChange={setSampleBody} rows={6} />
                <div className="button-row">
                  <button className="button primary" type="button" onClick={() => void publish()} disabled={busy}><Play size={16} /> Test and publish</button>
                  <button className="button secondary" type="button" onClick={() => void testEndpoint()} disabled={busy}>Run active test</button>
                </div>
                <details><summary>Generated curl</summary><pre>{endpointCurl(previewEndpoint, parsedBody)}</pre></details>
                <details><summary>Generated JavaScript fetch</summary><pre>{endpointFetch(previewEndpoint, parsedBody)}</pre></details>
              </div>
            ) : null}
            <div className="button-row">
              <button className="button primary" type="submit" disabled={busy}><Save size={16} /> Save draft</button>
              <button className="button secondary" type="button" onClick={() => setStep(Math.min(4, step + 1))}>Next</button>
            </div>
          </form>
          <PreviewPanel
            query={selected ? UPDATE_ENDPOINT : CREATE_ENDPOINT}
            variables={safeVariables(() => {
              const input = endpointInput(form);
              if (selected) {
                return { id: selected.id, input };
              }
              return { input } as JsonObject;
            })}
          />
          <ResultPanel title="Last Result" value={result} error={error} />
        </Panel>
      </div>
      <Panel title="Execution Logs" eyebrow={selected?.path ?? "No endpoint selected"} actions={selected ? <RefreshButton onClick={() => loadLogs()} busy={busy} /> : null}>
        <MiniTable items={logs} empty="No execution logs for this endpoint.">
          {(log) => (
            <div className="record-row vertical" key={log.id}>
              <div className="button-row"><StatusBadge value={log.status} /><span>{log.createdAt}</span></div>
              {log.error ? <small>{log.error}</small> : null}
              <JsonDetails title="requestSummary" value={log.requestSummary} />
              <JsonDetails title="responseSummary" value={log.responseSummary} />
            </div>
          )}
        </MiniTable>
      </Panel>
    </div>
  );
}

export function TenantsPage() {
  const [items, setItems] = useState<Tenant[]>([]);
  const [selected, setSelected] = useState<Tenant | null>(null);
  const [form, setForm] = useState({ name: "", route: "", tags: "", attributes: "{}" });
  const [filter, setFilter] = useState("");
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true); setError(null);
    try {
      const data = await gql<{ tenants: ListResult<Tenant> }>(TENANTS_QUERY, { status: enumOrNull(filter), limit: 100, offset: 0 });
      setItems(data.tenants.items);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);

  async function save() {
    setBusy(true); setError(null);
    try {
      const input = { name: form.name, route: compactNullable(form.route), tags: tagsFromText(form.tags), attributes: parseJsonObject(form.attributes, "attributes") };
      const tenant = selected
        ? (await gql<{ updateTenant: Tenant }>(UPDATE_TENANT, { id: selected.id, input })).updateTenant
        : (await gql<{ createTenant: Tenant }>(CREATE_TENANT, { input })).createTenant;
      setSelected(tenant); setResult(tenant); await load();
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function status(id: string, mutation: string) {
    setBusy(true); setError(null);
    try { setResult(await gql(mutation, { id })); await load(); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Operate" title="Tenants"><RefreshButton onClick={load} busy={busy} /></PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Tenant List">
          <div className="toolbar-grid"><select value={filter} onChange={(e) => setFilter(e.target.value)}><option value="">any</option><option>active</option><option>inactive</option><option>frozen</option><option>deleted</option></select><button className="button secondary" type="button" onClick={() => void load()}>Load</button></div>
          <MiniTable items={items} empty="No tenants loaded.">
            {(tenant) => <div className="record-row" key={tenant.id}><button className="link-button" type="button" onClick={() => { setSelected(tenant); setForm({ name: tenant.name, route: tenant.route ?? "", tags: textFromTags(tenant.tags), attributes: jsonString(tenant.attributes) }); }}><strong>{tenant.name}</strong><small>{tenant.id}</small></button><StatusBadge value={tenant.status} /><div className="button-row"><button className="button secondary" type="button" onClick={() => void status(tenant.id, ENABLE_TENANT)}>Enable</button><button className="button secondary" type="button" onClick={() => void status(tenant.id, DISABLE_TENANT)}>Disable</button><button className="button secondary" type="button" onClick={() => void status(tenant.id, FREEZE_TENANT)}>Freeze</button></div></div>}
          </MiniTable>
        </Panel>
        <Panel title={selected ? "Update Tenant" : "Create Tenant"}>
          <form className="stack" onSubmit={submit(save)}>
            <label><span>Name</span><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label><span>Route</span><input value={form.route} onChange={(e) => setForm({ ...form, route: e.target.value })} /></label>
            <label><span>Tags</span><input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} /></label>
            <JsonTextarea label="Attributes" value={form.attributes} onChange={(value) => setForm({ ...form, attributes: value })} />
            <button className="button primary" type="submit" disabled={busy}><Save size={16} /> Save</button>
          </form>
          <ResultPanel title="Last Result" value={result} error={error} />
        </Panel>
      </div>
    </div>
  );
}

export function ProfilesPage() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [versions, setVersions] = useState<ProfileVersion[]>([]);
  const [selected, setSelected] = useState<Profile | null>(null);
  const [form, setForm] = useState({ tenantId: "", objectKind: "entity", kind: "device", key: "", displayName: "", description: "", status: "active" });
  const [versionForm, setVersionForm] = useState({ version: "1", jsonSchema: "{}", uiSchema: "{}", status: "active" });
  const [filter, setFilter] = useState({ objectKind: "entity", kind: "", status: "" });
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true); setError(null);
    try {
      const data = await gql<{ profiles: ListResult<Profile> }>(PROFILES_QUERY, { objectKind: compactNullable(filter.objectKind), kind: compactNullable(filter.kind), status: compactNullable(filter.status), limit: 100, offset: 0 });
      setProfiles(data.profiles.items);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function loadVersions(profileId: string) {
    const data = await gql<{ profileVersions: ProfileVersion[] }>(PROFILE_VERSIONS_QUERY, { profileId });
    setVersions(data.profileVersions);
  }
  useEffect(() => { void load(); }, []);

  async function saveProfile() {
    setBusy(true); setError(null);
    try {
      const input = { tenantId: compactNullable(form.tenantId), objectKind: form.objectKind, kind: form.kind, key: form.key, displayName: form.displayName, description: compactNullable(form.description), status: compactNullable(form.status) };
      const profile = selected
        ? (await gql<{ updateProfile: Profile }>(UPDATE_PROFILE, {
            id: selected.id,
            input: {
              displayName: form.displayName,
              description: compactNullable(form.description),
              status: compactNullable(form.status),
            },
          })).updateProfile
        : (await gql<{ createProfile: Profile }>(CREATE_PROFILE, { input })).createProfile;
      setSelected(profile); setResult(profile); await load(); await loadVersions(profile.id);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function createVersion() {
    if (!selected) { setError("Select or create a profile first."); return; }
    setBusy(true); setError(null);
    try {
      const data = await gql<{ createProfileVersion: ProfileVersion }>(CREATE_PROFILE_VERSION, { profileId: selected.id, input: { version: Number(versionForm.version), jsonSchema: parseJsonObject(versionForm.jsonSchema, "JSON schema"), uiSchema: parseJsonObject(versionForm.uiSchema, "UI schema"), status: compactNullable(versionForm.status) } });
      setResult(data.createProfileVersion); await loadVersions(selected.id);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Operate" title="Profiles"><RefreshButton onClick={load} busy={busy} /></PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Profiles">
          <div className="toolbar-grid"><input value={filter.objectKind} onChange={(e) => setFilter({ ...filter, objectKind: e.target.value })} /><input placeholder="kind" value={filter.kind} onChange={(e) => setFilter({ ...filter, kind: e.target.value })} /><select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })}><option value="">any</option><option>active</option><option>deprecated</option><option>disabled</option></select><button className="button secondary" type="button" onClick={() => void load()}>Load</button></div>
          <MiniTable items={profiles} empty="No profiles loaded.">
            {(profile) => <div className="record-row" key={profile.id}><button className="link-button" type="button" onClick={() => { setSelected(profile); setForm({ tenantId: profile.tenantId ?? "", objectKind: profile.objectKind, kind: profile.kind, key: profile.key, displayName: profile.displayName, description: profile.description ?? "", status: profile.status }); void loadVersions(profile.id); }}><strong>{profile.displayName}</strong><small>{profile.objectKind}:{profile.kind}:{profile.key}</small></button><StatusBadge value={profile.status} /></div>}
          </MiniTable>
        </Panel>
        <Panel title={selected ? "Edit Profile" : "Create Profile"}>
          <form className="stack" onSubmit={submit(saveProfile)}>
            <div className="grid-2 compact"><label><span>Tenant ID</span><input value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Object kind</span><input value={form.objectKind} onChange={(e) => setForm({ ...form, objectKind: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Kind</span><input value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Key</span><input value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Display name</span><input required value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></label><label><span>Status</span><select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}><option>active</option><option>deprecated</option><option>disabled</option></select></label></div>
            <label><span>Description</span><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
            <div className="button-row"><button className="button primary" type="submit" disabled={busy}>Save profile</button><button className="button secondary" type="button" onClick={() => { setSelected(null); setVersions([]); setForm({ tenantId: "", objectKind: "entity", kind: "device", key: "", displayName: "", description: "", status: "active" }); }}>New</button></div>
          </form>
          <form className="stack form-section" onSubmit={submit(createVersion)}>
            <h3>Create profile version</h3>
            <div className="grid-2 compact"><label><span>Version</span><input type="number" value={versionForm.version} onChange={(e) => setVersionForm({ ...versionForm, version: e.target.value })} /></label><label><span>Status</span><input value={versionForm.status} onChange={(e) => setVersionForm({ ...versionForm, status: e.target.value })} /></label></div>
            <JsonTextarea label="JSON schema" value={versionForm.jsonSchema} onChange={(value) => setVersionForm({ ...versionForm, jsonSchema: value })} />
            <JsonTextarea label="UI schema" value={versionForm.uiSchema} onChange={(value) => setVersionForm({ ...versionForm, uiSchema: value })} />
            <button className="button secondary" type="submit" disabled={busy || !selected}>Create version</button>
          </form>
          <MiniTable items={versions} empty="No versions loaded.">
            {(version) => <div className="record-row vertical" key={version.id}><div><strong>v{version.version}</strong> <StatusBadge value={version.status} /></div><JsonDetails title="JSON schema" value={version.jsonSchema} /><JsonDetails title="UI schema" value={version.uiSchema} /></div>}
          </MiniTable>
          <ResultPanel title="Last Result" value={result} error={error} />
        </Panel>
      </div>
    </div>
  );
}

export function EntitiesPage() {
  const [entities, setEntities] = useState<Entity[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [versions, setVersions] = useState<ProfileVersion[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [selected, setSelected] = useState<Entity | null>(null);
  const [form, setForm] = useState({ tenantId: "", kind: "device", profileId: "", profileVersionId: "", name: "", attributes: "{}" });
  const [schemaAttrs, setSchemaAttrs] = useState<JsonObject>({});
  const [filter, setFilter] = useState({ kind: "", tenantId: "", profileId: "", status: "active" });
  const [password, setPassword] = useState("");
  const [apiKeyForm, setApiKeyForm] = useState({ expiresAt: "", description: "" });
  const [apiKey, setApiKey] = useState<ApiKeyResponse | null>(null);
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true); setError(null);
    try {
      const [entityData, profileData] = await Promise.all([
        gql<{ entities: ListResult<Entity> }>(ENTITIES_QUERY, { kind: enumOrNull(filter.kind), tenantId: compactNullable(filter.tenantId), profileId: compactNullable(filter.profileId), status: enumOrNull(filter.status), limit: 100, offset: 0 }),
        gql<{ profiles: ListResult<Profile> }>(PROFILES_QUERY, { objectKind: "entity", status: "active", limit: 100, offset: 0 }),
      ]);
      setEntities(entityData.entities.items); setProfiles(profileData.profiles.items);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);
  useEffect(() => {
    if (!form.profileId) { setVersions([]); return; }
    gql<{ profileVersions: ProfileVersion[] }>(PROFILE_VERSIONS_QUERY, { profileId: form.profileId }).then((data) => setVersions(data.profileVersions)).catch((caught) => setError(errorMessage(caught)));
  }, [form.profileId]);

  const selectedVersion = versions.find((version) => version.id === form.profileVersionId) ?? versions[0];
  const selectedProfile = profiles.find((profile) => profile.id === form.profileId);

  async function createEntity() {
    setBusy(true); setError(null);
    try {
      const attrs = selectedVersion && isJsonObject(selectedVersion.jsonSchema) ? schemaAttrs : parseJsonObject(form.attributes, "attributes");
      const input: JsonObject = { tenantId: compactNullable(form.tenantId), name: form.name, attributes: attrs };
      if (form.profileId) { input.profileId = form.profileId; }
      if (form.profileVersionId) { input.profileVersionId = form.profileVersionId; }
      if (!form.profileId) { input.kind = form.kind; }
      const data = await gql<{ createEntity: Entity }>(CREATE_ENTITY, { input });
      setResult(data.createEntity); setSelected(data.createEntity); await load();
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function loadCredentials(entity = selected) {
    if (!entity) { return; }
    setBusy(true); setError(null);
    try {
      const data = await gql<{ credentials: ListResult<Credential> }>(CREDENTIALS_QUERY, { entityId: entity.id });
      setCredentials(data.credentials.items);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function createPassword() {
    if (!selected) { setError("Select an entity first."); return; }
    setBusy(true); setError(null);
    try { setResult(await gql(CREATE_PASSWORD, { entityId: selected.id, password })); setPassword(""); await loadCredentials(selected); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function createApiKeyCredential() {
    if (!selected) { setError("Select an entity first."); return; }
    setBusy(true); setError(null); setApiKey(null);
    try {
      const data = await gql<{ createApiKey: ApiKeyResponse }>(CREATE_API_KEY, { entityId: selected.id, input: { expiresAt: compactNullable(apiKeyForm.expiresAt), description: compactNullable(apiKeyForm.description) } });
      setApiKey(data.createApiKey); setResult(data.createApiKey); await loadCredentials(selected);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function revoke(credentialId: string) {
    if (!selected) { return; }
    setBusy(true); setError(null);
    try { setResult(await gql(REVOKE_CREDENTIAL, { entityId: selected.id, credentialId })); await loadCredentials(selected); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Operate" title="Entities"><RefreshButton onClick={load} busy={busy} /></PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Entity List">
          <div className="toolbar-grid"><select value={filter.kind} onChange={(e) => setFilter({ ...filter, kind: e.target.value })}><option value="">any kind</option><option>human</option><option>device</option><option>service</option><option>workload</option><option>application</option></select><input placeholder="tenantId" value={filter.tenantId} onChange={(e) => setFilter({ ...filter, tenantId: e.target.value })} /><input placeholder="profileId" value={filter.profileId} onChange={(e) => setFilter({ ...filter, profileId: e.target.value })} /><select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })}><option value="">any status</option><option>active</option><option>inactive</option><option>suspended</option></select><button className="button secondary" type="button" onClick={() => void load()}>Load</button></div>
          <MiniTable items={entities} empty="No entities loaded.">
            {(entity) => <div className="record-row" key={entity.id}><button className="link-button" type="button" onClick={() => { setSelected(entity); void loadCredentials(entity); }}><strong>{entity.name}</strong><small>{entity.kind} · {entity.id}</small></button><StatusBadge value={entity.status} /></div>}
          </MiniTable>
        </Panel>
        <Panel title="Create Entity From Profile">
          <form className="stack" onSubmit={submit(createEntity)}>
            <div className="grid-2 compact"><label><span>Tenant ID</span><input value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value })} /></label><label><span>Kind fallback</span><select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option>human</option><option>device</option><option>service</option><option>workload</option><option>application</option></select></label><label><span>Profile</span><select value={form.profileId} onChange={(e) => setForm({ ...form, profileId: e.target.value, profileVersionId: "" })}><option value="">No profile</option>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.displayName} ({profile.kind}/{profile.key})</option>)}</select></label><label><span>Profile version</span><select value={form.profileVersionId} onChange={(e) => setForm({ ...form, profileVersionId: e.target.value })}><option value="">active/latest</option>{versions.map((version) => <option key={version.id} value={version.id}>v{version.version} · {version.status}</option>)}</select></label></div>
            <label><span>Name</span><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <div className="badge-row"><StatusBadge value={selectedProfile?.kind ?? form.kind} />{selectedVersion ? <StatusBadge value={`version ${selectedVersion.version}`} /> : null}</div>
            {selectedVersion && isJsonObject(selectedVersion.jsonSchema) ? <JsonSchemaForm schema={selectedVersion.jsonSchema} value={schemaAttrs} onChange={setSchemaAttrs} /> : null}
            <JsonTextarea label="Attributes JSON fallback" value={form.attributes} onChange={(value) => setForm({ ...form, attributes: value })} />
            <button className="button primary" type="submit" disabled={busy}>Create entity</button>
          </form>
          <ResultPanel title="Last Result" value={result} error={error} />
        </Panel>
      </div>
      <Panel title="Credentials" eyebrow={selected?.name ?? "No entity selected"}>
        <div className="grid-2 compact">
          <form className="stack" onSubmit={submit(createPassword)}><label><span>Password</span><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label><button className="button secondary" type="submit" disabled={busy || !selected}>Create password</button></form>
          <form className="stack" onSubmit={submit(createApiKeyCredential)}><label><span>API key description</span><input value={apiKeyForm.description} onChange={(e) => setApiKeyForm({ ...apiKeyForm, description: e.target.value })} /></label><label><span>Expires at RFC3339</span><input value={apiKeyForm.expiresAt} onChange={(e) => setApiKeyForm({ ...apiKeyForm, expiresAt: e.target.value })} /></label><button className="button secondary" type="submit" disabled={busy || !selected}>Create API key</button></form>
        </div>
        {apiKey ? <div className="notice danger"><KeyRound size={16} /><span>API key is shown once: <code>{apiKey.key}</code></span></div> : null}
        <MiniTable items={credentials} empty="No credentials loaded.">
          {(credential) => <div className="record-row" key={credential.id}><div><strong>{credential.kind}</strong><small>{credential.identifier ?? credential.id}</small></div><StatusBadge value={credential.status} /><button className="button secondary danger-button" type="button" onClick={() => void revoke(credential.id)}>Revoke</button></div>}
        </MiniTable>
      </Panel>
    </div>
  );
}

export function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [members, setMembers] = useState<Entity[]>([]);
  const [selected, setSelected] = useState<Group | null>(null);
  const [filter, setFilter] = useState({ tenantId: "" });
  const [form, setForm] = useState({ tenantId: "", name: "", description: "" });
  const [memberEntityId, setMemberEntityId] = useState("");
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true); setError(null);
    try {
      const [groupData, entityData] = await Promise.all([
        gql<{ groups: ListResult<Group> }>(GROUPS_QUERY, { tenantId: compactNullable(filter.tenantId), limit: 100, offset: 0 }),
        gql<{ entities: ListResult<Entity> }>(ENTITIES_QUERY, { limit: 100, offset: 0 }),
      ]);
      setGroups(groupData.groups.items);
      setEntities(entityData.entities.items);
      if (selected && !groupData.groups.items.some((group) => group.id === selected.id)) {
        setSelected(null);
        setMembers([]);
      }
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function loadMembers(group = selected) {
    if (!group) { setMembers([]); return; }
    setBusy(true); setError(null);
    try {
      const data = await gql<{ groupMembers: Entity[] }>(GROUP_MEMBERS_QUERY, { groupId: group.id });
      setMembers(data.groupMembers);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  useEffect(() => { void load(); }, []);

  async function createGroup() {
    setBusy(true); setError(null);
    try {
      const data = await gql<{ createGroup: Group }>(CREATE_GROUP, { input: { tenantId: compactNullable(form.tenantId), name: form.name, description: compactNullable(form.description) } });
      setResult(data.createGroup);
      setSelected(data.createGroup);
      setForm({ tenantId: "", name: "", description: "" });
      await load();
      await loadMembers(data.createGroup);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function deleteGroup(id: string) {
    setBusy(true); setError(null);
    try {
      setResult(await gql(DELETE_GROUP, { id }));
      if (selected?.id === id) {
        setSelected(null);
        setMembers([]);
      }
      await load();
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function addMember() {
    if (!selected || !memberEntityId) { return; }
    setBusy(true); setError(null);
    try {
      setResult(await gql(ADD_GROUP_MEMBER, { groupId: selected.id, entityId: memberEntityId }));
      setMemberEntityId("");
      await loadMembers(selected);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  async function removeMember(entityId: string) {
    if (!selected) { return; }
    setBusy(true); setError(null);
    try {
      setResult(await gql(REMOVE_GROUP_MEMBER, { groupId: selected.id, entityId }));
      await loadMembers(selected);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }

  const memberIds = new Set(members.map((member) => member.id));
  const availableEntities = entities.filter((entity) => !memberIds.has(entity.id));

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Operate" title="Groups"><RefreshButton onClick={load} busy={busy} /></PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Group List">
          <div className="toolbar-grid"><input placeholder="tenantId" value={filter.tenantId} onChange={(e) => setFilter({ ...filter, tenantId: e.target.value })} /><button className="button secondary" type="button" onClick={() => void load()}>Load</button></div>
          <MiniTable items={groups} empty="No groups loaded.">
            {(group) => <div className="record-row" key={group.id}><button className="link-button" type="button" onClick={() => { setSelected(group); void loadMembers(group); }}><strong>{group.name}</strong><small>{group.tenantId ?? "platform"} · {group.id}</small></button><button className="button secondary danger-button" type="button" onClick={() => void deleteGroup(group.id)}><Trash2 size={16} /> Delete</button></div>}
          </MiniTable>
        </Panel>
        <Panel title="Create Group">
          <form className="stack" onSubmit={submit(createGroup)}>
            <div className="grid-2 compact"><label><span>Tenant ID</span><input value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value })} /></label><label><span>Name</span><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label></div>
            <label><span>Description</span><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
            <button className="button primary" type="submit" disabled={busy}>Create group</button>
          </form>
          <ResultPanel title="Last Result" value={result} error={error} />
        </Panel>
      </div>
      <Panel title="Members" eyebrow={selected?.name ?? "No group selected"}>
        <form className="button-row" onSubmit={submit(addMember)}>
          <select value={memberEntityId} onChange={(e) => setMemberEntityId(e.target.value)} disabled={!selected}>
            <option value="">Choose entity</option>
            {availableEntities.map((entity) => <option key={entity.id} value={entity.id}>{entity.name} ({entity.kind})</option>)}
          </select>
          <button className="button secondary" type="submit" disabled={busy || !selected || !memberEntityId}><Plus size={16} /> Add member</button>
        </form>
        <MiniTable items={members} empty="No members loaded.">
          {(entity) => <div className="record-row" key={entity.id}><div><strong>{entity.name}</strong><small>{entity.kind} · {entity.id}</small></div><StatusBadge value={entity.status} /><button className="button secondary danger-button" type="button" onClick={() => void removeMember(entity.id)}>Remove</button></div>}
        </MiniTable>
      </Panel>
    </div>
  );
}

export function ResourcesPage() {
  const [items, setItems] = useState<Resource[]>([]);
  const [selected, setSelected] = useState<Resource | null>(null);
  const [form, setForm] = useState({ tenantId: "", kind: "channel", name: "", ownerId: "", attributes: "{}" });
  const [filter, setFilter] = useState({ kind: "", tenantId: "" });
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true); setError(null);
    try { const data = await gql<{ resources: ListResult<Resource> }>(RESOURCES_QUERY, { kind: compactNullable(filter.kind), tenantId: compactNullable(filter.tenantId), limit: 100, offset: 0 }); setItems(data.resources.items); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);
  async function save() {
    setBusy(true); setError(null);
    try {
      const resource = selected
        ? (await gql<{ updateResource: Resource }>(UPDATE_RESOURCE, {
            id: selected.id,
            input: {
              name: compactNullable(form.name),
              attributes: parseJsonObject(form.attributes, "attributes"),
            },
          })).updateResource
        : (await gql<{ createResource: Resource }>(CREATE_RESOURCE, {
            input: {
              tenantId: compactNullable(form.tenantId),
              kind: form.kind,
              name: compactNullable(form.name),
              ownerId: compactNullable(form.ownerId),
              attributes: parseJsonObject(form.attributes, "attributes"),
            },
          })).createResource;
      setSelected(resource); setResult(resource); await load();
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function remove(id: string) { setBusy(true); setError(null); try { setResult(await gql(DELETE_RESOURCE, { id })); await load(); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); } }
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Secure" title="Resources"><RefreshButton onClick={load} busy={busy} /></PageHeader>
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Protected Objects"><div className="toolbar-grid"><input placeholder="kind" value={filter.kind} onChange={(e) => setFilter({ ...filter, kind: e.target.value })} /><input placeholder="tenantId" value={filter.tenantId} onChange={(e) => setFilter({ ...filter, tenantId: e.target.value })} /><button className="button secondary" type="button" onClick={() => void load()}>Load</button></div><MiniTable items={items} empty="No resources loaded.">{(resource) => <div className="record-row" key={resource.id}><button className="link-button" type="button" onClick={() => { setSelected(resource); setForm({ tenantId: resource.tenantId ?? "", kind: resource.kind, name: resource.name ?? "", ownerId: resource.ownerId ?? "", attributes: jsonString(resource.attributes) }); }}><strong>{resource.name ?? resource.kind}</strong><small>{resource.kind} · {resource.id}</small></button><button className="button secondary danger-button" type="button" onClick={() => void remove(resource.id)}><Trash2 size={16} /> Delete</button></div>}</MiniTable></Panel>
        <Panel title={selected ? "Update Resource" : "Create Resource"}><form className="stack" onSubmit={submit(save)}><div className="grid-2 compact"><label><span>Tenant ID</span><input value={form.tenantId} onChange={(e) => setForm({ ...form, tenantId: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Kind</span><input value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })} disabled={Boolean(selected)} /></label><label><span>Name</span><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label><label><span>Owner ID</span><input value={form.ownerId} onChange={(e) => setForm({ ...form, ownerId: e.target.value })} disabled={Boolean(selected)} /></label></div><JsonTextarea label="Attributes" value={form.attributes} onChange={(value) => setForm({ ...form, attributes: value })} /><div className="button-row"><button className="button primary" type="submit" disabled={busy}>Save</button><button className="button secondary" type="button" onClick={() => { setSelected(null); setForm({ tenantId: "", kind: "channel", name: "", ownerId: "", attributes: "{}" }); }}>New</button></div></form><ResultPanel title="Last Result" value={result} error={error} /></Panel>
      </div>
    </div>
  );
}

export function PoliciesPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [policies, setPolicies] = useState<PolicyBinding[]>([]);
  const [filter, setFilter] = useState({ tenantId: "" });
  const [form, setForm] = useState({ tenantId: "", subjectKind: "entity", subjectId: "", grantKind: "capability", grantId: "", scopeKind: "object", scopeRef: "", effect: "allow", conditions: "{}" });
  const [createOpen, setCreateOpen] = useState(false);
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function loadPolicyContext(tenantId: string | null) {
    const [entityData, groupData, roleData, capData, resourceData, policyData] = await Promise.all([
      gql<{ entities: ListResult<Entity> }>(ENTITIES_QUERY, { tenantId, limit: 100, offset: 0 }),
      gql<{ groups: ListResult<Group> }>(GROUPS_QUERY, { tenantId, limit: 100, offset: 0 }),
      gql<{ roles: ListResult<Role> }>(ROLES_QUERY, { tenantId, limit: 100, offset: 0 }),
      gql<{ capabilities: ListResult<Capability> }>(CAPABILITIES_QUERY, { tenantId }),
      gql<{ resources: ListResult<Resource> }>(RESOURCES_QUERY, { tenantId, limit: 100, offset: 0 }),
      gql<{ policies: ListResult<PolicyBinding> }>(POLICIES_QUERY, { tenantId, limit: 50, offset: 0 }),
    ]);
    setEntities(entityData.entities.items); setGroups(groupData.groups.items); setRoles(roleData.roles.items); setCapabilities(capData.capabilities.items); setResources(resourceData.resources.items); setPolicies(policyData.policies.items);
  }

  async function load() {
    setBusy(true); setError(null);
    try {
      const tenantData = await gql<{ tenants: ListResult<Tenant> }>(TENANTS_QUERY, { limit: 100, offset: 0 });
      setTenants(tenantData.tenants.items);
      const tenantId = compactNullable(filter.tenantId);
      try {
        await loadPolicyContext(tenantId);
      } catch (caught) {
        const fallbackTenant = tenantData.tenants.items[0];
        if (tenantId || !fallbackTenant || !errorMessage(caught).toLowerCase().includes("forbidden")) {
          throw caught;
        }
        setFilter({ tenantId: fallbackTenant.id });
        setForm((current) => current.tenantId ? current : { ...current, tenantId: fallbackTenant.id, scopeKind: "tenant", scopeRef: fallbackTenant.id });
        await loadPolicyContext(fallbackTenant.id);
      }
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);

  function openCreatePolicy() {
    const tenantId = compactNullable(filter.tenantId) ?? "";
    setForm((current) => ({
      ...current,
      tenantId: current.tenantId || tenantId,
      scopeKind: current.scopeKind === "object" && tenantId ? "tenant" : current.scopeKind,
      scopeRef: current.scopeRef || tenantId,
    }));
    setCreateOpen(true);
  }

  async function createPolicy() {
    setBusy(true); setError(null);
    try {
      const input = { tenantId: compactNullable(form.tenantId), subjectKind: form.subjectKind, subjectId: form.subjectId, grantKind: form.grantKind, grantId: form.grantId, scopeKind: form.scopeKind, scopeRef: compactNullable(form.scopeRef), effect: form.effect, conditions: parseJsonObject(form.conditions, "conditions") };
      const data = await gql<{ createPolicy: PolicyBinding }>(CREATE_POLICY, { input });
      setResult(data.createPolicy);
      setCreateOpen(false);
      await load();
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  const subjectOptions: Array<{ id: string; name: string }> =
    form.subjectKind === "entity" ? entities.map((entity) => ({ id: entity.id, name: entity.name })) : groups.map((group) => ({ id: group.id, name: group.name }));
  const grantOptions: Array<{ id: string; name: string }> =
    form.grantKind === "capability" ? capabilities.map((capability) => ({ id: capability.id, name: capability.name })) : roles.map((role) => ({ id: role.id, name: role.name }));

  const tenantById = useMemo(() => new Map(tenants.map((tenant) => [tenant.id, tenant])), [tenants]);
  const entityById = useMemo(() => new Map(entities.map((entity) => [entity.id, entity])), [entities]);
  const groupById = useMemo(() => new Map(groups.map((group) => [group.id, group])), [groups]);
  const roleById = useMemo(() => new Map(roles.map((role) => [role.id, role])), [roles]);
  const capabilityById = useMemo(() => new Map(capabilities.map((capability) => [capability.id, capability])), [capabilities]);
  const resourceById = useMemo(() => new Map(resources.map((resource) => [resource.id, resource])), [resources]);

  function shortId(id: string | null | undefined): string {
    return id ? `${id.slice(0, 8)}...${id.slice(-6)}` : "*";
  }

  function policyTenant(policy: PolicyBinding): { title: string; detail: string } {
    if (!policy.tenantId) {
      return { title: "Platform", detail: "platform policy" };
    }
    const tenant = tenantById.get(policy.tenantId);
    return { title: tenant?.name ?? shortId(policy.tenantId), detail: policy.tenantId };
  }

  function policySubject(policy: PolicyBinding): { title: string; detail: string } {
    if (policy.subjectKind === "entity") {
      const entity = entityById.get(policy.subjectId);
      return { title: entity?.name ?? shortId(policy.subjectId), detail: `${entity?.kind ?? "entity"} · ${policy.subjectId}` };
    }
    const group = groupById.get(policy.subjectId);
    return { title: group?.name ?? shortId(policy.subjectId), detail: `group · ${policy.subjectId}` };
  }

  function policyGrant(policy: PolicyBinding): { title: string; detail: string } {
    if (policy.grantKind === "role") {
      const role = roleById.get(policy.grantId);
      return { title: role?.name ?? shortId(policy.grantId), detail: `role · ${policy.grantId}` };
    }
    const capability = capabilityById.get(policy.grantId);
    return { title: capability?.name ?? shortId(policy.grantId), detail: `capability · ${policy.grantId}` };
  }

  function policyScope(policy: PolicyBinding): { title: string; detail: string } {
    if (policy.scopeKind === "platform") {
      return { title: "Platform", detail: "all tenants and objects" };
    }
    if (policy.scopeKind === "tenant" && policy.scopeRef) {
      const tenant = tenantById.get(policy.scopeRef);
      return { title: tenant?.name ?? shortId(policy.scopeRef), detail: `tenant · ${policy.scopeRef}` };
    }
    if (policy.scopeKind === "object" && policy.scopeRef) {
      const resource = resourceById.get(policy.scopeRef);
      return { title: resource?.name ?? shortId(policy.scopeRef), detail: `${resource?.kind ?? "object"} · ${policy.scopeRef}` };
    }
    return { title: policy.scopeRef ?? "*", detail: policy.scopeKind };
  }

  function hasConditions(policy: PolicyBinding): boolean {
    return isJsonObject(policy.conditions) ? Object.keys(policy.conditions).length > 0 : Boolean(policy.conditions);
  }

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Secure" title="Policies">
        <RefreshButton onClick={load} busy={busy} />
        <button className="button primary" type="button" onClick={openCreatePolicy} disabled={busy}><Plus size={16} /> Create policy</button>
      </PageHeader>
      <ErrorNotice message={error} />
      <Panel title="Policy List" eyebrow={`${policies.length} loaded`} className="policy-list-panel">
        <div className="toolbar-grid policy-toolbar">
          <select value={filter.tenantId} onChange={(event) => setFilter({ tenantId: event.target.value })}>
            <option value="">All policies</option>
            {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
          </select>
          <button className="button secondary" type="button" onClick={() => void load()} disabled={busy}><Search size={16} /> Load</button>
        </div>
        <MiniTable items={policies} empty="No policies loaded.">
          {(policy) => {
            const tenant = policyTenant(policy);
            const subject = policySubject(policy);
            const grant = policyGrant(policy);
            const scope = policyScope(policy);
            return (
              <div className="policy-row" key={policy.id}>
                <div className="policy-row-header">
                  <StatusBadge value={policy.effect} />
                  <div>
                    <strong>{subject.title}</strong>
                    <span>{policy.effect === "allow" ? "can use" : "is denied"} {grant.title}</span>
                  </div>
                </div>
                <dl className="policy-fields">
                  <div><dt>Subject</dt><dd>{subject.title}<small>{subject.detail}</small></dd></div>
                  <div><dt>Grant</dt><dd>{grant.title}<small>{grant.detail}</small></dd></div>
                  <div><dt>Scope</dt><dd>{scope.title}<small>{scope.detail}</small></dd></div>
                  <div><dt>Policy Tenant</dt><dd>{tenant.title}<small>{tenant.detail}</small></dd></div>
                </dl>
                {hasConditions(policy) ? <JsonDetails title="conditions" value={policy.conditions} /> : <p className="policy-no-conditions">No conditions</p>}
              </div>
            );
          }}
        </MiniTable>
      </Panel>
      {createOpen ? (
        <div className="modal-backdrop" role="presentation">
          <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="create-policy-title">
            <div className="modal-header">
              <div>
                <p className="eyebrow">WHO / CAN DO / ON / WHEN / EFFECT</p>
                <h2 id="create-policy-title">Create Policy</h2>
              </div>
              <button className="button secondary icon-button" type="button" onClick={() => setCreateOpen(false)} aria-label="Close"><X size={18} /></button>
            </div>
            <form className="stack" onSubmit={submit(createPolicy)}>
              <div className="builder-grid">
                <label><span>WHO</span><select value={form.subjectKind} onChange={(e) => setForm({ ...form, subjectKind: e.target.value, subjectId: "" })}><option>entity</option><option>group</option></select></label>
                <label><span>Subject</span><select value={form.subjectId} onChange={(e) => setForm({ ...form, subjectId: e.target.value })}><option value="">Choose subject</option>{subjectOptions.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
                <label><span>CAN DO</span><select value={form.grantKind} onChange={(e) => setForm({ ...form, grantKind: e.target.value, grantId: "" })}><option>capability</option><option>role</option></select></label>
                <label><span>Grant</span><select value={form.grantId} onChange={(e) => setForm({ ...form, grantId: e.target.value })}><option value="">Choose grant</option>{grantOptions.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
                <label><span>Policy tenant</span><select value={form.tenantId} onChange={(e) => { const tenantId = e.target.value; setForm({ ...form, tenantId, scopeRef: form.scopeKind === "tenant" ? tenantId : form.scopeRef }); }}><option value="">Platform</option>{tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}</select></label>
                <label><span>ON</span><select value={form.scopeKind} onChange={(e) => { const scopeKind = e.target.value; setForm({ ...form, scopeKind, scopeRef: scopeKind === "tenant" ? form.tenantId : "" }); }}><option>platform</option><option>tenant</option><option>object_kind</option><option>object_type</option><option>object</option></select></label>
                <label><span>Scope ref</span><input list="policy-scope-refs" value={form.scopeRef} onChange={(e) => setForm({ ...form, scopeRef: e.target.value })} /></label>
                <label><span>EFFECT</span><select value={form.effect} onChange={(e) => setForm({ ...form, effect: e.target.value })}><option>allow</option><option>deny</option></select></label>
              </div>
              <datalist id="policy-scope-refs">
                {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                {resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name ?? resource.kind}</option>)}
              </datalist>
              <JsonTextarea label="WHEN conditions JSON" value={form.conditions} onChange={(value) => setForm({ ...form, conditions: value })} />
              <div className="button-row modal-actions">
                <button className="button secondary" type="button" onClick={() => setCreateOpen(false)}>Cancel</button>
                <button className="button primary" type="submit" disabled={busy}>Create policy</button>
              </div>
            </form>
            {result ? <ResultPanel title="Last Created" value={result} error={null} /> : null}
            <PreviewPanel
              query={CREATE_POLICY}
              variables={safeVariables(() => ({
                input: {
                  tenantId: compactNullable(form.tenantId),
                  subjectKind: form.subjectKind,
                  subjectId: form.subjectId,
                  grantKind: form.grantKind,
                  grantId: form.grantId,
                  scopeKind: form.scopeKind,
                  scopeRef: compactNullable(form.scopeRef),
                  effect: form.effect,
                  conditions: parseJsonObject(form.conditions, "conditions"),
                },
              }))}
            />
          </section>
        </div>
      ) : null}
    </div>
  );
}

export function AuthzPage() {
  const [form, setForm] = useState({ subjectId: "", action: "read", resourceId: "", objectKind: "", objectId: "", context: "{}" });
  const [bulk, setBulk] = useState("[\n  {\n    \"subjectId\": \"\",\n    \"action\": \"read\",\n    \"context\": {}\n  }\n]");
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  function input(): JsonObject {
    return { subjectId: form.subjectId, action: form.action, resourceId: compactNullable(form.resourceId), objectKind: compactNullable(form.objectKind), objectId: compactNullable(form.objectId), context: parseJsonObject(form.context, "context") };
  }
  async function run(name: "check" | "explain") {
    setBusy(true); setError(null);
    try {
      if (name === "check") {
        const data = await gql<{ authzCheck: AuthzResponse }>(AUTHZ_CHECK, { input: input() });
        setResult(data.authzCheck);
      } else {
        const data = await gql<{ authzExplain: AuthzExplainResponse }>(AUTHZ_EXPLAIN, { input: input() });
        setResult(data.authzExplain);
      }
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  async function runBulk() {
    setBusy(true); setError(null);
    try {
      const parsed = parseJson(bulk, "bulk input");
      if (!Array.isArray(parsed)) { throw new Error("bulk input must be an array"); }
      const data = await gql<{ authzBulkCheck: AuthzResponse[] }>(AUTHZ_BULK_CHECK, { input: parsed as JsonValue[] });
      setResult(data.authzBulkCheck);
    } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  const response = result && !Array.isArray(result) && typeof result === "object" ? (result as Partial<AuthzResponse>) : null;
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Secure" title="Authz Tester" />
      <ErrorNotice message={error} />
      <div className="grid-2">
        <Panel title="Single Check">
          <form className="stack" onSubmit={preventDefault(() => run("check"))}>
            <div className="grid-2 compact"><label><span>Subject ID</span><input value={form.subjectId} onChange={(e) => setForm({ ...form, subjectId: e.target.value })} /></label><label><span>Action</span><input value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} /></label><label><span>Resource ID</span><input value={form.resourceId} onChange={(e) => setForm({ ...form, resourceId: e.target.value })} /></label><label><span>Object kind</span><input value={form.objectKind} onChange={(e) => setForm({ ...form, objectKind: e.target.value })} /></label><label><span>Object ID</span><input value={form.objectId} onChange={(e) => setForm({ ...form, objectId: e.target.value })} /></label></div>
            <JsonTextarea label="Context" value={form.context} onChange={(value) => setForm({ ...form, context: value })} />
            <div className="button-row"><button className="button primary" type="button" onClick={() => void run("check")} disabled={busy}>Run check</button><button className="button secondary" type="button" onClick={() => void run("explain")} disabled={busy}>Explain</button></div>
          </form>
          {response ? <div className="notice"><StatusBadge value={response.allowed ?? null} /><span>{response.reason}{response.allowed === false ? " · Consider adding an allow policy or checking for explicit deny conditions." : ""}</span></div> : null}
          <PreviewPanel query={AUTHZ_CHECK} variables={safeVariables(() => ({ input: input() }))} />
        </Panel>
        <Panel title="Bulk Check">
          <JsonTextarea label="Bulk input" value={bulk} onChange={setBulk} rows={12} />
          <button className="button secondary" type="button" onClick={() => void runBulk()} disabled={busy}>Run bulk</button>
        </Panel>
      </div>
      <ResultPanel title="Result" value={result} error={error} />
    </div>
  );
}

type IntrospectionTypeRef = {
  kind: string;
  name: string | null;
  ofType?: IntrospectionTypeRef | null;
};
type IntrospectionArg = {
  name: string;
  description?: string | null;
  defaultValue?: string | null;
  type: IntrospectionTypeRef;
};
type IntrospectionField = {
  name: string;
  description?: string | null;
  args?: IntrospectionArg[] | null;
  type: IntrospectionTypeRef;
};
type IntrospectionInputField = IntrospectionArg;
type IntrospectionEnumValue = { name: string; description?: string | null };
type IntrospectionType = {
  name: string | null;
  kind: string;
  description?: string | null;
  fields?: IntrospectionField[] | null;
  inputFields?: IntrospectionInputField[] | null;
  enumValues?: IntrospectionEnumValue[] | null;
};
type IntrospectionData = { __schema: { queryType?: { name: string } | null; mutationType?: { name: string } | null; types: IntrospectionType[] } };

type RootKind = "query" | "mutation";

function typeToString(type: IntrospectionTypeRef | undefined | null): string {
  if (!type) { return "Unknown"; }
  if (type.kind === "NON_NULL") { return `${typeToString(type.ofType)}!`; }
  if (type.kind === "LIST") { return `[${typeToString(type.ofType)}]`; }
  return type.name ?? "Unknown";
}

function namedType(type: IntrospectionTypeRef | undefined | null): IntrospectionTypeRef | null {
  let current = type;
  while (current?.ofType) { current = current.ofType; }
  return current ?? null;
}

function isLeafType(type: IntrospectionTypeRef, typeMap: Record<string, IntrospectionType>): boolean {
  const named = namedType(type);
  if (!named) { return true; }
  const full = named.name ? typeMap[named.name] : null;
  return ["SCALAR", "ENUM"].includes(full?.kind ?? named.kind);
}

function indent(depth: number): string {
  return "  ".repeat(depth);
}

function selectionFor(
  type: IntrospectionTypeRef,
  typeMap: Record<string, IntrospectionType>,
  depth = 2,
): string {
  if (isLeafType(type, typeMap) || depth > 4) { return ""; }
  const named = namedType(type);
  const objectType = named?.name ? typeMap[named.name] : null;
  const fields = (objectType?.fields ?? []).filter((field) => !field.name.startsWith("__"));
  const selected = fields.slice(0, depth === 2 ? 10 : 6).flatMap((field) => {
    if (isLeafType(field.type, typeMap)) {
      return [`${indent(depth)}${field.name}`];
    }
    const nested = selectionFor(field.type, typeMap, depth + 1);
    return nested ? [`${indent(depth)}${field.name} {\n${nested}\n${indent(depth)}}`] : [];
  });
  return selected.join("\n");
}

function placeholderFor(
  type: IntrospectionTypeRef,
  name: string,
  typeMap: Record<string, IntrospectionType>,
): JsonValue {
  const named = namedType(type);
  const typeName = named?.name ?? "";
  const lowered = name.toLowerCase();
  if (lowered.includes("limit")) { return 20; }
  if (lowered.includes("offset")) { return 0; }
  if (typeName === "Boolean") { return false; }
  if (typeName === "Int" || typeName === "Float") { return 0; }
  if (typeName === "ID") { return "paste-id-here"; }
  if (typeName === "JSON" || typeName === "JSONObject" || typeName === "Value") { return {}; }
  const full = typeName ? typeMap[typeName] : null;
  if (full?.kind === "ENUM") { return full.enumValues?.[0]?.name ?? ""; }
  if (full?.kind === "INPUT_OBJECT") {
    return Object.fromEntries(
      (full.inputFields ?? []).map((field) => [field.name, placeholderFor(field.type, field.name, typeMap)]),
    ) as JsonObject;
  }
  return `paste-${name}-here`;
}

function buildOperation(
  rootKind: RootKind,
  field: IntrospectionField,
  typeMap: Record<string, IntrospectionType>,
): { query: string; variables: JsonObject } {
  const variables: JsonObject = {};
  const definitions: string[] = [];
  const args: string[] = [];
  for (const arg of field.args ?? []) {
    definitions.push(`$${arg.name}: ${typeToString(arg.type)}`);
    args.push(`${arg.name}: $${arg.name}`);
    variables[arg.name] = placeholderFor(arg.type, arg.name, typeMap);
  }
  const opName = `${rootKind === "mutation" ? "Run" : "Get"}${field.name[0].toUpperCase()}${field.name.slice(1)}`;
  const selection = selectionFor(field.type, typeMap);
  const selectionBlock = selection ? ` {\n${selection}\n  }` : "";
  const query = [
    `${rootKind} ${opName}${definitions.length ? `(${definitions.join(", ")})` : ""} {`,
    `  ${field.name}${args.length ? `(${args.join(", ")})` : ""}${selectionBlock}`,
    "}",
    "",
  ].join("\n");
  return { query, variables };
}

function rootType(schema: IntrospectionData["__schema"], rootKind: RootKind, typeMap: Record<string, IntrospectionType>): IntrospectionType | null {
  const name = rootKind === "mutation" ? schema.mutationType?.name : schema.queryType?.name;
  return name ? typeMap[name] ?? null : null;
}

function GraphqlDeveloperPage({ title, eyebrow }: { title: string; eyebrow: string }) {
  const [schema, setSchema] = useState<IntrospectionData["__schema"] | null>(null);
  const [rootKind, setRootKind] = useState<RootKind>("query");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("{ health }");
  const [variables, setVariables] = useState("{}");
  const [response, setResponse] = useState<GraphqlEnvelope<JsonObject> | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<unknown>();
  async function loadSchema() {
    setBusy(true); setError(null);
    try { const data = await gql<IntrospectionData>(INTROSPECTION_QUERY, {}, { auth: false }); setSchema(data.__schema); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  useEffect(() => { void loadSchema(); }, []);
  useEffect(() => {
    void gql(HEALTH_QUERY, {}, { auth: false })
      .then((result) => setHealth(result))
      .catch((caught) => setHealth({ error: errorMessage(caught) }));
  }, []);
  async function run() {
    setBusy(true); setError(null);
    try { setResponse(await rawGql<JsonObject>(query, parseJsonObject(variables, "variables"))); } catch (caught) { setError(errorMessage(caught)); } finally { setBusy(false); }
  }
  const typeMap = useMemo(
    () => Object.fromEntries((schema?.types ?? []).flatMap((type) => (type.name ? [[type.name, type]] : []))) as Record<string, IntrospectionType>,
    [schema],
  );
  const operations = useMemo(() => {
    if (!schema) { return []; }
    const root = rootType(schema, rootKind, typeMap);
    return (root?.fields ?? [])
      .filter((field) => !field.name.startsWith("__"))
      .filter((field) => {
        const haystack = `${field.name} ${field.description ?? ""} ${(field.args ?? []).map((arg) => arg.name).join(" ")}`.toLowerCase();
        return haystack.includes(search.trim().toLowerCase());
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [rootKind, schema, search, typeMap]);
  const explorerVariables = safeVariables(() => parseJsonObject(variables, "variables"));
  const authState = getToken() ? "Token saved" : "No token saved";

  return (
    <div className="page-stack">
      <PageHeader eyebrow={eyebrow} title={title}><RefreshButton onClick={loadSchema} busy={busy} label="Refresh schema" /></PageHeader>
      <ErrorNotice message={error} />
      <div className="dashboard-grid">
        <Panel title="Developer Status" eyebrow={authState}>
          <dl className="token-details"><div><dt>GraphQL endpoint</dt><dd>/graphql</dd></div><div><dt>Schema types</dt><dd>{schema?.types.length ?? "not loaded"}</dd></div><div><dt>Health</dt><dd>{isJsonObject(health as JsonValue) ? JSON.stringify(health) : "checking"}</dd></div></dl>
        </Panel>
        <Panel title="Starter Examples" eyebrow="One-click operations">
          <div className="button-row wrap"><button className="button secondary" type="button" onClick={() => { setQuery("{ health }"); setVariables("{}"); }}>Health</button><button className="button secondary" type="button" onClick={() => { setQuery("query Tenants($limit: Int = 20, $offset: Int = 0) {\n  tenants(limit: $limit, offset: $offset) {\n    items { id name route status createdAt updatedAt }\n    total\n  }\n}\n"); setVariables("{\n  \"limit\": 20,\n  \"offset\": 0\n}"); }}>List tenants</button><button className="button secondary" type="button" onClick={() => { setQuery("query Groups($limit: Int = 20, $offset: Int = 0) {\n  groups(limit: $limit, offset: $offset) {\n    items { id name tenantId description createdAt updatedAt }\n    total\n  }\n}\n"); setVariables("{\n  \"limit\": 20,\n  \"offset\": 0\n}"); }}>List groups</button><button className="button secondary" type="button" onClick={() => { setQuery("mutation CreateTenant($input: CreateTenantInput!) {\n  createTenant(input: $input) { id name route status }\n}\n"); setVariables("{\n  \"input\": {\n    \"name\": \"factory-a\",\n    \"route\": \"factory-a\"\n  }\n}"); }}>Create tenant</button><button className="button secondary" type="button" onClick={() => { setQuery("mutation CreateGroup($input: CreateGroupInput!) {\n  createGroup(input: $input) { id name tenantId description }\n}\n"); setVariables("{\n  \"input\": {\n    \"name\": \"operators\"\n  }\n}"); }}>Create group</button><button className="button secondary" type="button" onClick={() => { setQuery("mutation Login($input: LoginInput!) {\n  login(input: $input) { token entityId sessionId expiresAt }\n}\n"); setVariables("{\n  \"input\": {\n    \"identifier\": \"atom-admin\",\n    \"secret\": \"change-me\",\n    \"kind\": \"password\"\n  }\n}"); }}>Login</button></div>
        </Panel>
      </div>
      <div className="grid-2 playground-grid">
        <Panel title="Schema Builder" eyebrow={`${operations.length} ${rootKind} fields`} className="schema-builder-panel">
          <div className="button-row"><button className={`button ${rootKind === "query" ? "primary" : "secondary"}`} type="button" onClick={() => setRootKind("query")}>Queries</button><button className={`button ${rootKind === "mutation" ? "primary" : "secondary"}`} type="button" onClick={() => setRootKind("mutation")}>Mutations</button></div>
          <label><span>Search fields</span><input placeholder="groups, createGroup, authzCheck" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
          <div className="schema-builder-scroll">
            <MiniTable items={operations} empty="No schema loaded.">
              {(field) => {
                const built = buildOperation(rootKind, field, typeMap);
                return <button className="record-row link-button vertical" type="button" key={field.name} onClick={() => { setQuery(built.query); setVariables(jsonString(built.variables)); }}><strong>{field.name}</strong><small>{typeToString(field.type)} · {(field.args ?? []).map((arg) => arg.name).join(", ") || "no args"}</small><span>{field.description}</span></button>;
              }}
            </MiniTable>
          </div>
        </Panel>
        <div className="stack">
          <Panel title="Query Editor">
            <div className="stack"><label><span>GraphQL</span><textarea rows={12} spellCheck={false} value={query} onChange={(e) => setQuery(e.target.value)} /></label><JsonTextarea label="Variables" value={variables} onChange={setVariables} rows={6} /><div className="button-row"><button className="button primary" type="button" onClick={() => void run()} disabled={busy}>Run</button><CopyButton value={graphQlCurl(query, explorerVariables)} label="curl" /><CopyButton value={graphQlFetch(query, explorerVariables)} label="fetch" /></div></div>
          </Panel>
          <ResultPanel title="Response" value={response} error={error} />
        </div>
      </div>
    </div>
  );
}

export function ExplorerPage() {
  return <GraphqlDeveloperPage title="GraphQL Explorer" eyebrow="System" />;
}

export function PlaygroundPage() {
  return <GraphqlDeveloperPage title="Developer Playground" eyebrow="GraphQL" />;
}

export function SettingsPage() {
  const [health, setHealth] = useState<unknown>();
  const [message, setMessage] = useState<string | null>(null);
  async function checkHealth() {
    setMessage(null);
    try { setHealth(await gql(HEALTH_QUERY, {}, { auth: false })); } catch (caught) { setMessage(errorMessage(caught)); }
  }
  function clearLocalData() {
    clearToken();
    localStorage.removeItem("atom.graphql.console.recipes");
    localStorage.removeItem("atom.graphql.console.examples");
    setMessage("Local console token, recipes, and examples were cleared.");
  }
  return (
    <div className="page-stack">
      <PageHeader eyebrow="System" title="Settings" />
      <ErrorNotice message={message && message.startsWith("GraphQL") ? message : null} />
      <div className="grid-2">
        <Panel title="Token Handling" eyebrow="Local browser state"><p className="empty-state">Token storage key: <code>atom.graphql.console.token</code></p><button className="button secondary danger-button spaced" type="button" onClick={clearLocalData}>Clear local console data</button>{message && !message.startsWith("GraphQL") ? <div className="notice">{message}</div> : null}</Panel>
        <Panel title="Console Config" eyebrow="Read-only"><dl className="token-details"><div><dt>GraphQL endpoint</dt><dd>/graphql</dd></div><div><dt>Custom endpoint prefix</dt><dd>/api/custom/*</dd></div><div><dt>Endpoint execution limit</dt><dd>1 MiB body, 5 second backend timeout</dd></div></dl><button className="button secondary" type="button" onClick={() => void checkHealth()}>Check GraphQL health</button><ResultPanel title="Health" value={health} /></Panel>
      </div>
    </div>
  );
}
