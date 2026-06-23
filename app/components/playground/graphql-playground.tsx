"use client";

import { Copy, DatabaseZap, Play, RotateCcw, Search } from "lucide-react";
import { useMemo, useState } from "react";
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
  const [isRunning, setIsRunning] = useState(false);
  const [isLoadingSchema, setIsLoadingSchema] = useState(false);

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

  async function loadSchema() {
    setIsLoadingSchema(true);
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
      setSchemaTypes(payload.data?.__schema?.types ?? []);
      toast.success("Schema loaded");
    } catch (caught) {
      toast.error(
        caught instanceof Error ? caught.message : "Schema request failed",
      );
    } finally {
      setIsLoadingSchema(false);
    }
  }

  function loadStarter(starter: (typeof STARTER_OPERATIONS)[number]) {
    setQuery(starter.query);
    setVariables(starter.variables);
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
