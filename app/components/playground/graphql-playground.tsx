"use client";

import {
  AlertCircle,
  Copy,
  DatabaseZap,
  Play,
  RotateCcw,
  Search,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { JsonEditor } from "@/components/ui/json-editor";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

const DEFAULT_QUERY = `query HealthCheck {
  health
}`;

const INTROSPECTION_QUERY = `query PlaygroundSchema {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      description
      fields {
        name
        description
        args {
          name
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}`;

const STARTER_OPERATIONS = [
  {
    name: "Health",
    description: "Check that the Atom GraphQL API is reachable.",
    query: DEFAULT_QUERY,
    variables: "{}",
  },
  {
    name: "Tenants",
    description: "List tenant records with pagination.",
    query: `query Tenants($limit: Int = 20, $offset: Int = 0) {
  tenants(limit: $limit, offset: $offset) {
    total
    items {
      id
      name
      alias
      status
      createdAt
    }
  }
}`,
    variables: '{\n  "limit": 20,\n  "offset": 0\n}',
  },
  {
    name: "Entities",
    description: "List entities visible to the current session.",
    query: `query Entities($limit: Int = 20, $offset: Int = 0) {
  entities(limit: $limit, offset: $offset) {
    total
    items {
      id
      kind
      name
      tenantId
      status
    }
  }
}`,
    variables: '{\n  "limit": 20,\n  "offset": 0\n}',
  },
  {
    name: "Authorization Explain",
    description: "Inspect the authorization decision for a subject/action.",
    query: `mutation Explain($input: AuthzCheckInput!) {
  authzExplain(input: $input) {
    allowed
    reason
    matchedBinding
    evaluatedBindings
  }
}`,
    variables: `{
  "input": {
    "subjectId": "",
    "action": "manage",
    "objectKind": "platform",
    "context": {}
  }
}`,
  },
] as const;

type PlaygroundResult = {
  body: string;
  durationMs: number;
  ok: boolean;
  status: number;
};

type SchemaField = {
  name: string;
  description?: string | null;
  args?: Array<{ name: string; type?: TypeRef | null }> | null;
  type?: TypeRef | null;
};

type SchemaType = {
  name?: string | null;
  kind: string;
  description?: string | null;
  fields?: SchemaField[] | null;
};

type TypeRef = {
  kind: string;
  name?: string | null;
  ofType?: TypeRef | null;
};

type SchemaResponse = {
  data?: {
    __schema?: {
      types?: SchemaType[] | null;
    } | null;
  };
  errors?: Array<{ message: string }>;
};

export function GraphqlPlayground() {
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [variables, setVariables] = useState("{}");
  const [operationName, setOperationName] = useState("");
  const [result, setResult] = useState<PlaygroundResult | null>(null);
  const [schemaTypes, setSchemaTypes] = useState<SchemaType[]>([]);
  const [schemaSearch, setSchemaSearch] = useState("");
  const [operationSearch, setOperationSearch] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [isLoadingSchema, setIsLoadingSchema] = useState(false);
  const [schemaError, setSchemaError] = useState<string | null>(null);

  const requestPayload = useMemo(() => {
    const payload: Record<string, unknown> = { query };
    const parsedVariables = parseJsonObject(variables);
    if (parsedVariables.ok && Object.keys(parsedVariables.value).length > 0) {
      payload.variables = parsedVariables.value;
    }
    if (operationName.trim()) {
      payload.operationName = operationName.trim();
    }
    return payload;
  }, [operationName, query, variables]);

  const fetchSnippet = useMemo(
    () => `const response = await fetch("/api/graphql", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(${JSON.stringify(requestPayload, null, 2)}),
});

const payload = await response.json();`,
    [requestPayload],
  );

  const curlSnippet = useMemo(
    () => `curl -X POST http://localhost:3000/api/graphql \\
  -H 'content-type: application/json' \\
  -H 'cookie: atom_session=<session-cookie>' \\
  --data '${JSON.stringify(requestPayload)}'`,
    [requestPayload],
  );

  const filteredSchema = useMemo(() => {
    const search = schemaSearch.trim().toLowerCase();
    const visibleTypes = schemaTypes.filter(
      (type) =>
        type.name &&
        ["OBJECT", "INPUT_OBJECT", "ENUM", "SCALAR"].includes(type.kind) &&
        !type.name.startsWith("__"),
    );

    if (!search) {
      return visibleTypes.slice(0, 24);
    }

    return visibleTypes
      .filter((type) => {
        const fieldMatch = type.fields?.some((field) =>
          field.name.toLowerCase().includes(search),
        );
        return type.name?.toLowerCase().includes(search) || fieldMatch;
      })
      .slice(0, 24);
  }, [schemaSearch, schemaTypes]);

  const groupedOperations = useMemo(() => {
    const queryType = schemaTypes.find((type) => type.name === "Query");
    const mutationType = schemaTypes.find((type) => type.name === "Mutation");
    const queries = (queryType?.fields ?? []).map((field) => ({
      field,
      kind: "query" as const,
    }));
    const mutations = (mutationType?.fields ?? []).map((field) => ({
      field,
      kind: "mutation" as const,
    }));
    const all = groupOperations([...queries, ...mutations]);
    const term = operationSearch.trim().toLowerCase();
    if (!term) return all;
    return all
      .map((group) => ({
        ...group,
        entries: group.entries.filter(
          (entry) =>
            entry.field.name.toLowerCase().includes(term) ||
            (entry.field.description ?? "").toLowerCase().includes(term),
        ),
      }))
      .filter((group) => group.entries.length > 0);
  }, [operationSearch, schemaTypes]);

  const totalOperationCount = useMemo(() => {
    const queryType = schemaTypes.find((type) => type.name === "Query");
    const mutationType = schemaTypes.find((type) => type.name === "Mutation");
    return (
      (queryType?.fields?.length ?? 0) + (mutationType?.fields?.length ?? 0)
    );
  }, [schemaTypes]);

  async function executeOperation() {
    const parsedVariables = parseJsonObject(variables);
    if (!parsedVariables.ok) {
      setResult({
        body: JSON.stringify(
          { errors: [{ message: parsedVariables.error }] },
          null,
          2,
        ),
        durationMs: 0,
        ok: false,
        status: 0,
      });
      return;
    }

    setIsRunning(true);
    const startedAt = performance.now();
    try {
      const response = await fetch("/api/graphql", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          query,
          variables: parsedVariables.value,
          operationName: operationName.trim() || undefined,
        }),
      });
      const text = await response.text();
      setResult({
        body: formatResponseBody(text),
        durationMs: Math.round(performance.now() - startedAt),
        ok: response.ok,
        status: response.status,
      });
    } catch (caught) {
      setResult({
        body: JSON.stringify(
          {
            errors: [
              {
                message:
                  caught instanceof Error
                    ? caught.message
                    : "GraphQL request failed",
              },
            ],
          },
          null,
          2,
        ),
        durationMs: Math.round(performance.now() - startedAt),
        ok: false,
        status: 0,
      });
    } finally {
      setIsRunning(false);
    }
  }

  async function loadSchema(options?: { silent?: boolean }) {
    setIsLoadingSchema(true);
    setSchemaError(null);
    try {
      const response = await fetch("/api/graphql", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      });
      const payload = (await response.json()) as SchemaResponse;
      if (!response.ok || payload.errors?.length) {
        throw new Error(
          payload.errors?.map((error) => error.message).join("; ") ??
            "Schema request failed",
        );
      }
      const types = payload.data?.__schema?.types ?? [];
      setSchemaTypes(types);
      if (types.length === 0) {
        setSchemaError(
          "Introspection returned no types. Set ATOM_GRAPHQL_INTROSPECTION_ENABLED=true and restart Atom.",
        );
      }
      if (!options?.silent) {
        toast.success("Schema loaded");
      }
    } catch (caught) {
      const message =
        caught instanceof Error ? caught.message : "Schema request failed";
      setSchemaError(message);
      if (!options?.silent) {
        toast.error(message);
      }
    } finally {
      setIsLoadingSchema(false);
    }
  }

  // Auto-load once on mount so operators land on a populated Operations panel
  // instead of an empty "Load the schema…" placeholder. Silent on this first
  // load — the error state below surfaces failures without a toast on boot.
  // biome-ignore lint/correctness/useExhaustiveDependencies: fire-once mount effect
  useEffect(() => {
    void loadSchema({ silent: true });
  }, []);

  function loadStarter(starter: (typeof STARTER_OPERATIONS)[number]) {
    setQuery(starter.query);
    setVariables(starter.variables);
    setOperationName("");
    setResult(null);
  }

  function loadOperation(kind: "query" | "mutation", field: SchemaField) {
    setQuery(buildOperationTemplate(kind, field));
    setVariables(buildVariablesTemplate(field));
    setOperationName("");
    setResult(null);
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
      <div className="grid gap-4">
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Request</CardTitle>
                <CardDescription>Execute GraphQL requests.</CardDescription>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setQuery(DEFAULT_QUERY);
                    setVariables("{}");
                    setOperationName("");
                    setResult(null);
                  }}
                >
                  <RotateCcw data-icon="inline-start" />
                  Reset
                </Button>
                <Button
                  type="button"
                  onClick={() => void executeOperation()}
                  disabled={isRunning}
                >
                  <Play data-icon="inline-start" />
                  {isRunning ? "Running" : "Run"}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              Operation name
              <input
                className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={operationName}
                onChange={(event) => setOperationName(event.target.value)}
                placeholder="Optional when the document has one operation"
              />
            </label>
            <div className="grid gap-2">
              <Label htmlFor="playground-query">Query</Label>
              <Textarea
                id="playground-query"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                spellCheck={false}
                className="min-h-80 resize-y font-mono text-xs"
              />
            </div>
            <div className="grid gap-2">
              <div className="text-sm font-medium">Variables</div>
              <JsonEditor
                value={variables}
                onChange={setVariables}
                className="[&_.cm-editor]:min-h-32"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Response</CardTitle>
                <CardDescription>
                  Results, errors, and transport status from the last request.
                </CardDescription>
              </div>
              {result ? (
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={result.ok ? "secondary" : "destructive"}>
                    {result.status ? `HTTP ${result.status}` : "Local error"}
                  </Badge>
                  <Badge variant="outline">{result.durationMs} ms</Badge>
                </div>
              ) : null}
            </div>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="response">
              <TabsList>
                <TabsTrigger value="response">Response</TabsTrigger>
                <TabsTrigger value="fetch">Fetch</TabsTrigger>
                <TabsTrigger value="curl">curl</TabsTrigger>
              </TabsList>
              <TabsContent value="response" className="mt-3">
                <JsonEditor
                  value={
                    result?.body ??
                    JSON.stringify(
                      { message: "Run an operation to inspect the response." },
                      null,
                      2,
                    )
                  }
                  className="[&_.cm-editor]:min-h-64"
                />
              </TabsContent>
              <TabsContent value="fetch" className="mt-3">
                <Snippet value={fetchSnippet} />
              </TabsContent>
              <TabsContent value="curl" className="mt-3">
                <Snippet value={curlSnippet} />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      <aside className="grid gap-4 self-start">
        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Operations</CardTitle>
                <CardDescription>
                  Every query and mutation the schema exposes, grouped by
                  domain. Click any entry to load a template into the editor.
                </CardDescription>
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => void loadSchema()}
                disabled={isLoadingSchema}
              >
                <DatabaseZap data-icon="inline-start" />
                {isLoadingSchema
                  ? "Loading"
                  : totalOperationCount > 0
                    ? "Refresh"
                    : "Load"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3">
            {schemaError ? (
              <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{schemaError}</span>
              </p>
            ) : null}
            <label className="relative block">
              <Search className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted-foreground" />
              <input
                className="h-9 w-full rounded-md border border-input bg-background pr-3 pl-9 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={operationSearch}
                onChange={(event) => setOperationSearch(event.target.value)}
                placeholder={
                  totalOperationCount > 0
                    ? `Search ${totalOperationCount} operations`
                    : "Search operations"
                }
              />
            </label>
            {totalOperationCount > 0 ? (
              <div className="grid max-h-[65vh] gap-2 overflow-auto pr-1">
                {groupedOperations.length ? (
                  groupedOperations.map((group) => (
                    <details
                      key={group.name}
                      className="rounded-md border"
                      open={
                        operationSearch.length > 0 ||
                        group.name === "certificates" ||
                        group.name === "pki"
                      }
                    >
                      <summary className="flex cursor-pointer items-center justify-between gap-2 px-3 py-2 text-sm font-medium">
                        <span>{group.label}</span>
                        <Badge variant="outline">{group.entries.length}</Badge>
                      </summary>
                      <ul className="grid gap-1 border-t p-2">
                        {group.entries.map((entry) => (
                          <li key={`${entry.kind}:${entry.field.name}`}>
                            <button
                              type="button"
                              className="grid w-full gap-0.5 rounded-md p-2 text-left transition-colors hover:bg-accent hover:text-accent-foreground"
                              onClick={() =>
                                loadOperation(entry.kind, entry.field)
                              }
                            >
                              <span className="flex items-center gap-2 font-mono text-xs">
                                <Badge
                                  variant={
                                    entry.kind === "mutation"
                                      ? "destructive"
                                      : "secondary"
                                  }
                                  className="px-1 py-0 text-[10px] uppercase"
                                >
                                  {entry.kind}
                                </Badge>
                                {entry.field.name}
                              </span>
                              {entry.field.description ? (
                                <span className="line-clamp-2 text-[11px] text-muted-foreground">
                                  {entry.field.description}
                                </span>
                              ) : null}
                              {entry.field.args &&
                              entry.field.args.length > 0 ? (
                                <span className="mt-1 flex flex-wrap gap-1 text-[10px] text-muted-foreground">
                                  {entry.field.args.map((arg) => (
                                    <span
                                      key={arg.name}
                                      className="rounded bg-muted px-1.5 py-0.5 font-mono"
                                    >
                                      {arg.name}: {formatTypeRef(arg.type)}
                                    </span>
                                  ))}
                                </span>
                              ) : null}
                            </button>
                          </li>
                        ))}
                      </ul>
                    </details>
                  ))
                ) : (
                  <p className="rounded-md border p-3 text-sm text-muted-foreground">
                    No operations match “{operationSearch}”.
                  </p>
                )}
              </div>
            ) : (
              <p className="rounded-md border p-3 text-sm text-muted-foreground">
                {isLoadingSchema
                  ? "Loading schema…"
                  : "Introspection has not returned any operations yet. Click Load."}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Starter Operations</CardTitle>
            <CardDescription>
              Load a known Atom operation into the editor.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2">
            {STARTER_OPERATIONS.map((starter) => (
              <button
                key={starter.name}
                type="button"
                className="rounded-md border p-3 text-left transition-colors hover:bg-accent hover:text-accent-foreground"
                onClick={() => loadStarter(starter)}
              >
                <span className="block text-sm font-medium">
                  {starter.name}
                </span>
                <span className="mt-1 block text-xs text-muted-foreground">
                  {starter.description}
                </span>
              </button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="gap-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Schema</CardTitle>
                <CardDescription>
                  Search introspection results for fields and types.
                </CardDescription>
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => void loadSchema()}
                disabled={isLoadingSchema}
              >
                <DatabaseZap data-icon="inline-start" />
                {isLoadingSchema ? "Loading" : "Load"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="grid gap-3">
            <label className="relative block">
              <Search className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted-foreground" />
              <input
                className="h-9 w-full rounded-md border border-input bg-background pr-3 pl-9 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                value={schemaSearch}
                onChange={(event) => setSchemaSearch(event.target.value)}
                placeholder="Search schema"
              />
            </label>
            <div className="grid max-h-130 gap-2 overflow-auto pr-1">
              {filteredSchema.length ? (
                filteredSchema.map((type) => (
                  <SchemaTypeCard
                    key={`${type.kind}:${type.name}`}
                    type={type}
                  />
                ))
              ) : (
                <p className="rounded-md border p-3 text-sm text-muted-foreground">
                  Load the schema to browse available operations.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      </aside>
    </div>
  );
}

function Snippet({ value }: { value: string }) {
  return (
    <div className="grid gap-2">
      <div className="flex justify-end">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copyToClipboard(value)}
        >
          <Copy data-icon="inline-start" />
          Copy
        </Button>
      </div>
      <pre className="max-h-80 overflow-auto rounded-md border bg-muted p-3 text-xs">
        <code>{value}</code>
      </pre>
    </div>
  );
}

function SchemaTypeCard({ type }: { type: SchemaType }) {
  const fields = type.fields?.slice(0, 8) ?? [];

  return (
    <div className="rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-medium">{type.name}</span>
        <Badge variant="outline">{type.kind}</Badge>
      </div>
      {type.description ? (
        <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">
          {type.description}
        </p>
      ) : null}
      {fields.length ? (
        <div className="mt-3 grid gap-1">
          {fields.map((field) => (
            <div
              key={field.name}
              className="flex min-w-0 items-center justify-between gap-2 text-xs"
            >
              <span className="truncate font-mono">{field.name}</span>
              <span className="truncate text-muted-foreground">
                {formatTypeRef(field.type)}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function parseJsonObject(
  source: string,
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  const trimmed = source.trim();
  if (!trimmed) {
    return { ok: true, value: {} };
  }

  try {
    const value = JSON.parse(trimmed) as unknown;
    if (!value || Array.isArray(value) || typeof value !== "object") {
      return { ok: false, error: "Variables must be a JSON object." };
    }
    return { ok: true, value: value as Record<string, unknown> };
  } catch (caught) {
    return {
      ok: false,
      error:
        caught instanceof Error
          ? caught.message
          : "Variables are invalid JSON.",
    };
  }
}

function formatResponseBody(text: string) {
  try {
    return JSON.stringify(JSON.parse(text) as unknown, null, 2);
  } catch {
    return JSON.stringify({ raw: text }, null, 2);
  }
}

function formatTypeRef(type?: TypeRef | null): string {
  if (!type) {
    return "unknown";
  }
  if (type.name) {
    return type.name;
  }
  if (type.ofType) {
    if (type.kind === "NON_NULL") {
      return `${formatTypeRef(type.ofType)}!`;
    }
    if (type.kind === "LIST") {
      return `[${formatTypeRef(type.ofType)}]`;
    }
    return formatTypeRef(type.ofType);
  }
  return type.kind;
}

async function copyToClipboard(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success("Copied");
  } catch {
    toast.error("Copy failed");
  }
}

// Domain grouping is derived from operation-name prefixes because GraphQL
// has no native namespace. The categories match how the Rust resolvers are
// organised (see src/graphql/ and src/certs/**/graphql.rs).
const OPERATION_GROUPS: Array<{
  name: string;
  label: string;
  matches: (name: string) => boolean;
}> = [
  {
    name: "pki",
    label: "PKI Authorities",
    matches: (name) =>
      name.startsWith("pkiAuthorit") ||
      name.startsWith("beginTenantAuthority") ||
      name.startsWith("provisionTenant") ||
      name.startsWith("beginAuthorityRetirement") ||
      name.startsWith("completeAuthorityRetirement") ||
      name.startsWith("transitionRetirement"),
  },
  {
    name: "certificates",
    label: "Certificates",
    matches: (name) =>
      name === "certificate" ||
      name === "certificates" ||
      name.startsWith("issueCertificate") ||
      name.startsWith("issueGeneratedCertificate") ||
      name.startsWith("renewCertificate") ||
      name.startsWith("renewGeneratedCertificate") ||
      name.startsWith("revokeCertificate") ||
      name.startsWith("revokeEntityCertificates") ||
      name.startsWith("bulkRevokeCertificates"),
  },
  {
    name: "tenants",
    label: "Tenants",
    matches: (name) =>
      name === "tenant" || name === "tenants" || name.endsWith("Tenant"),
  },
  {
    name: "entities",
    label: "Entities",
    matches: (name) =>
      name === "entity" || name === "entities" || name.endsWith("Entity"),
  },
  {
    name: "authz",
    label: "Authorization",
    matches: (name) =>
      name.startsWith("authz") ||
      name.startsWith("role") ||
      name.startsWith("permissionBlock") ||
      name.startsWith("directPolicy") ||
      name.startsWith("action"),
  },
  {
    name: "identity",
    label: "Identity & Sessions",
    matches: (name) =>
      name.startsWith("credential") ||
      name.startsWith("accessToken") ||
      name.startsWith("session") ||
      name.startsWith("me") ||
      name.startsWith("password") ||
      name.startsWith("shared"),
  },
  {
    name: "groups",
    label: "Groups",
    matches: (name) =>
      name === "group" || name === "groups" || name.endsWith("Group"),
  },
  {
    name: "resources",
    label: "Resources",
    matches: (name) =>
      name === "resource" || name === "resources" || name.endsWith("Resource"),
  },
  {
    name: "audit",
    label: "Audit & Health",
    matches: (name) =>
      name.startsWith("audit") || name === "health" || name === "systemStatus",
  },
];

type OperationEntry = { field: SchemaField; kind: "query" | "mutation" };
type OperationGroup = {
  name: string;
  label: string;
  entries: OperationEntry[];
};

function groupOperations(entries: OperationEntry[]): OperationGroup[] {
  const groups = new Map<string, OperationGroup>();
  for (const spec of OPERATION_GROUPS) {
    groups.set(spec.name, {
      name: spec.name,
      label: spec.label,
      entries: [],
    });
  }
  const other: OperationGroup = { name: "other", label: "Other", entries: [] };

  for (const entry of entries) {
    const spec = OPERATION_GROUPS.find((candidate) =>
      candidate.matches(entry.field.name),
    );
    if (spec) {
      groups.get(spec.name)?.entries.push(entry);
    } else {
      other.entries.push(entry);
    }
  }

  const ordered: OperationGroup[] = [];
  for (const spec of OPERATION_GROUPS) {
    const group = groups.get(spec.name);
    if (group && group.entries.length > 0) {
      group.entries.sort((a, b) => a.field.name.localeCompare(b.field.name));
      ordered.push(group);
    }
  }
  if (other.entries.length > 0) {
    other.entries.sort((a, b) => a.field.name.localeCompare(b.field.name));
    ordered.push(other);
  }
  return ordered;
}

function buildOperationTemplate(
  kind: "query" | "mutation",
  field: SchemaField,
): string {
  const args = field.args ?? [];
  const varSignature = args
    .map((arg) => `$${arg.name}: ${formatTypeRef(arg.type)}`)
    .join(", ");
  const argAssignment = args
    .map((arg) => `${arg.name}: $${arg.name}`)
    .join(", ");
  const returnKind = unwrapType(field.type)?.kind ?? "SCALAR";
  const body = returnKind === "OBJECT" ? " {\n    __typename\n  }" : "";
  const opName = capitalize(field.name);
  const header = varSignature ? `${opName}(${varSignature})` : opName;
  const call = argAssignment ? `${field.name}(${argAssignment})` : field.name;
  return `${kind} ${header} {\n  ${call}${body}\n}`;
}

function buildVariablesTemplate(field: SchemaField): string {
  const args = field.args ?? [];
  if (args.length === 0) {
    return "{}";
  }
  const object: Record<string, unknown> = {};
  for (const arg of args) {
    object[arg.name] = null;
  }
  return JSON.stringify(object, null, 2);
}

function unwrapType(type?: TypeRef | null): TypeRef | null {
  if (!type) return null;
  if (type.name) return type;
  return unwrapType(type.ofType ?? null);
}

function capitalize(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}
