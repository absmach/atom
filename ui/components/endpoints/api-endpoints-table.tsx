"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { EditorView, type ReactCodeMirrorProps } from "@uiw/react-codemirror";
import { Plus } from "lucide-react";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import * as React from "react";
import { type Control, useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import type { ApiEndpointRow } from "@/components/endpoints/api-endpoints-workspace";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/ui/data-table";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { JsonEditor } from "@/components/ui/json-editor";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const CREATE_MUTATION = `
  mutation CreateApiEndpoint($input: CreateApiEndpointInput!) {
    createApiEndpoint(input: $input) {
      id key name method path operationKind status createdAt
    }
  }
`;

const UPDATE_MUTATION = `
  mutation UpdateApiEndpoint($id: ID!, $input: UpdateApiEndpointInput!) {
    updateApiEndpoint(id: $id, input: $input) {
      id key name method path operationKind status updatedAt
    }
  }
`;

const DISABLE_MUTATION = `
  mutation DisableApiEndpoint($id: ID!) {
    disableApiEndpoint(id: $id) { id status }
  }
`;

const ENABLE_MUTATION = `
  mutation EnableApiEndpoint($id: ID!) {
    enableApiEndpoint(id: $id) { id status }
  }
`;

const ENTITY_NAME_QUERY = `
  query EndpointActorName($id: ID!) {
    entity(id: $id) { id name }
  }
`;

const CodeMirror = dynamic<ReactCodeMirrorProps>(
  () => import("@uiw/react-codemirror").then((m) => m.default),
  { ssr: false },
);
const CODE_EXTENSIONS = [EditorView.lineWrapping];

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const OPERATION_KINDS = ["query", "mutation"];
const AUTH_MODES = ["caller_context", "service_context"];
const STATUSES = ["draft", "active", "disabled"];

type EndpointInput = Record<string, unknown>;
const jsonString = z.string().refine(isJsonObject, "Must be valid JSON.");
const schema = z
  .object({
    key: z.string().trim().min(1, "Key is required."),
    name: z.string().trim().min(1, "Name is required."),
    description: z.string().trim(),
    method: z.string().refine((value) => HTTP_METHODS.includes(value), {
      message: "Choose a supported method.",
    }),
    path: z
      .string()
      .trim()
      .min(1, "Path is required.")
      .startsWith("/api/custom/", "Path must start with /api/custom/."),
    operationKind: z
      .string()
      .refine((value) => OPERATION_KINDS.includes(value), {
        message: "Choose a supported operation kind.",
      }),
    graphql: z.string().trim().min(1, "GraphQL operation is required."),
    authMode: z.string().refine((value) => AUTH_MODES.includes(value), {
      message: "Choose a supported auth mode.",
    }),
    serviceEntityId: z.string().trim(),
    variablesMapping: jsonString,
    requestSchema: jsonString,
    responseMapping: jsonString,
    status: z.string().refine((value) => STATUSES.includes(value), {
      message: "Choose a supported status.",
    }),
  })
  .superRefine((values, ctx) => {
    if (values.authMode === "service_context" && !values.serviceEntityId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Service entity ID is required for service_context.",
        path: ["serviceEntityId"],
      });
    }
  });
type FormValues = z.infer<typeof schema>;

type PanelState =
  | { mode: "create" }
  | { mode: "edit"; row: ApiEndpointRow }
  | { mode: "inspect"; row: ApiEndpointRow }
  | null;

type EndpointPreset = {
  label: string;
  description: string;
  values: Partial<FormValues>;
};

// variablesMapping uses dotted keys to build nested GraphQL variables.
// e.g. "input.name": "$body.name" → { input: { name: <value> } }
// Nested objects as values are NOT interpolated — only string "$source" values are.
const ENDPOINT_PRESETS: EndpointPreset[] = [
  {
    label: "Health Check",
    description: "Ping the backend health query.",
    values: {
      key: "health_check",
      name: "Health Check",
      description: "Returns OK when the backend is reachable.",
      method: "GET",
      path: "/api/custom/health",
      operationKind: "query",
      graphql: `query HealthCheck {\n  health\n}`,
      authMode: "caller_context",
      variablesMapping: "{}",
      requestSchema: "{}",
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Create Tenant",
    description: "Create a new tenant.",
    values: {
      key: "create_tenant",
      name: "Create Tenant",
      description: "Creates a new tenant with a name and optional alias.",
      method: "POST",
      path: "/api/custom/tenants",
      operationKind: "mutation",
      graphql: `mutation CreateTenant($input: CreateTenantInput!) {\n  createTenant(input: $input) {\n    id\n    name\n    alias\n    status\n    createdAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        { "input.name": "$body.name", "input.alias": "$body.alias" },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          required: ["name"],
          properties: {
            name: { type: "string" },
            alias: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Update Tenant",
    description: "Update an existing tenant by ID.",
    values: {
      key: "update_tenant",
      name: "Update Tenant",
      description: "Updates a tenant's name or alias.",
      method: "PATCH",
      path: "/api/custom/tenants/update",
      operationKind: "mutation",
      graphql: `mutation UpdateTenant($id: ID!, $input: UpdateTenantInput!) {\n  updateTenant(id: $id, input: $input) {\n    id\n    name\n    alias\n    status\n    updatedAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          id: "$query.id",
          "input.name": "$body.name",
          "input.alias": "$body.alias",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          properties: {
            name: { type: "string" },
            alias: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Create Entity",
    description: "Create a new entity (human, service, device, etc.).",
    values: {
      key: "create_entity",
      name: "Create Entity",
      description:
        "Creates an entity with a name, kind, optional alias, and optional tenant.",
      method: "POST",
      path: "/api/custom/entities",
      operationKind: "mutation",
      graphql: `mutation CreateEntity($input: CreateEntityInput!) {\n  createEntity(input: $input) {\n    id\n    name\n    alias\n    kind\n    status\n    createdAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          "input.name": "$body.name",
          "input.alias": "$body.alias",
          "input.kind": "$body.kind",
          "input.tenantId": "$body.tenantId",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          required: ["name"],
          properties: {
            name: { type: "string" },
            alias: { type: "string" },
            kind: { type: "string" },
            tenantId: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Update Entity",
    description: "Update an existing entity by ID.",
    values: {
      key: "update_entity",
      name: "Update Entity",
      description: "Updates an entity's name, alias, or attributes.",
      method: "PATCH",
      path: "/api/custom/entities/update",
      operationKind: "mutation",
      graphql: `mutation UpdateEntity($id: ID!, $input: UpdateEntityInput!) {\n  updateEntity(id: $id, input: $input) {\n    id\n    name\n    alias\n    kind\n    status\n    updatedAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          id: "$query.id",
          "input.name": "$body.name",
          "input.alias": "$body.alias",
          "input.attributes": "$body.attributes",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          properties: {
            name: { type: "string" },
            alias: { type: ["string", "null"] },
            attributes: { type: "object" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Create Resource",
    description: "Register a new resource.",
    values: {
      key: "create_resource",
      name: "Create Resource",
      description:
        "Creates a resource with an optional alias that can be referenced in policies.",
      method: "POST",
      path: "/api/custom/resources",
      operationKind: "mutation",
      graphql: `mutation CreateResource($input: CreateResourceInput!) {\n  createResource(input: $input) {\n    id\n    name\n    alias\n    kind\n    createdAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          "input.name": "$body.name",
          "input.alias": "$body.alias",
          "input.kind": "$body.kind",
          "input.tenantId": "$body.tenantId",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          required: ["name"],
          properties: {
            name: { type: "string" },
            alias: { type: "string" },
            kind: { type: "string" },
            tenantId: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Update Resource",
    description: "Update an existing resource by ID.",
    values: {
      key: "update_resource",
      name: "Update Resource",
      description: "Updates a resource's name, alias, or attributes.",
      method: "PATCH",
      path: "/api/custom/resources/update",
      operationKind: "mutation",
      graphql: `mutation UpdateResource($id: ID!, $input: UpdateResourceInput!) {\n  updateResource(id: $id, input: $input) {\n    id\n    name\n    alias\n    kind\n    updatedAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          id: "$query.id",
          "input.name": "$body.name",
          "input.alias": "$body.alias",
          "input.attributes": "$body.attributes",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          properties: {
            name: { type: "string" },
            alias: { type: ["string", "null"] },
            attributes: { type: "object" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Create Direct Policy",
    description: "Create an advanced direct policy.",
    values: {
      key: "create_direct_policy",
      name: "Create Direct Policy",
      description: "Creates a subject-to-permission-block direct policy.",
      method: "POST",
      path: "/api/custom/direct-policies",
      operationKind: "mutation",
      graphql: `mutation CreateDirectPolicy($input: CreateDirectPolicyInput!) {\n  createDirectPolicy(input: $input) {\n    id\n    tenantId\n    subjectKind\n    subjectId\n    permissionBlockId\n    createdAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          "input.tenantId": "$body.tenantId",
          "input.subjectKind": "$body.subjectKind",
          "input.subjectId": "$body.subjectId",
          "input.permissionBlockId": "$body.permissionBlockId",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          required: ["effect", "actions"],
          properties: {
            effect: { type: "string" },
            actions: { type: "array", items: { type: "string" } },
            entityId: { type: "string" },
            resourceId: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Update Policy",
    description: "Update an existing policy by ID.",
    values: {
      key: "update_policy",
      name: "Update Policy",
      description: "Updates a policy's effect, actions, or status.",
      method: "PATCH",
      path: "/api/custom/policies/update",
      operationKind: "mutation",
      graphql: `mutation UpdatePolicy($id: ID!, $input: UpdatePolicyInput!) {\n  updatePolicy(id: $id, input: $input) {\n    id\n    effect\n    actions\n    status\n    updatedAt\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          id: "$query.id",
          "input.effect": "$body.effect",
          "input.actions": "$body.actions",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          properties: {
            effect: { type: "string" },
            actions: { type: "array", items: { type: "string" } },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
  {
    label: "Authorization Check",
    description: "Evaluate whether an entity can perform an action.",
    values: {
      key: "authz_check",
      name: "Authorization Check",
      description:
        "Explains the authorization decision for a given entity, action, and resource.",
      method: "POST",
      path: "/api/custom/authz/check",
      operationKind: "query",
      graphql: `query AuthzCheck($entityId: ID!, $action: String!, $resourceId: ID) {\n  explain(entityId: $entityId, action: $action, resourceId: $resourceId) {\n    decision\n    reason\n  }\n}`,
      authMode: "caller_context",
      variablesMapping: JSON.stringify(
        {
          entityId: "$body.entityId",
          action: "$body.action",
          resourceId: "$body.resourceId",
        },
        null,
        2,
      ),
      requestSchema: JSON.stringify(
        {
          type: "object",
          required: ["entityId", "action"],
          properties: {
            entityId: { type: "string" },
            action: { type: "string" },
            resourceId: { type: "string" },
          },
        },
        null,
        2,
      ),
      responseMapping: "{}",
      status: "draft",
    },
  },
];

export function ApiEndpointsTable({
  rows,
  total,
  page,
  limit,
}: {
  rows: ApiEndpointRow[];
  total: number;
  page: number;
  limit: number;
}) {
  const router = useRouter();
  const [panel, setPanel] = React.useState<PanelState>(null);

  const create = useMutation({
    mutationFn: (input: EndpointInput) =>
      graphqlClient({ query: CREATE_MUTATION, variables: { input } }),
    onSuccess: () => {
      toast.success("Endpoint created");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const update = useMutation({
    mutationFn: ({ id, input }: { id: string; input: EndpointInput }) =>
      graphqlClient({ query: UPDATE_MUTATION, variables: { id, input } }),
    onSuccess: () => {
      toast.success("Endpoint updated");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      graphqlClient({
        query: enable ? ENABLE_MUTATION : DISABLE_MUTATION,
        variables: { id },
      }),
    onSuccess: (_, { enable }) => {
      toast.success(enable ? "Endpoint enabled" : "Endpoint disabled");
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const columns: ColumnDef<ApiEndpointRow>[] = [
    {
      accessorKey: "key",
      header: "Key",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{String(getValue())}</span>
      ),
    },
    { accessorKey: "name", header: "Name" },
    {
      accessorKey: "method",
      header: "Method",
      cell: ({ getValue }) => (
        <Badge variant="secondary">{String(getValue())}</Badge>
      ),
    },
    {
      accessorKey: "path",
      header: "Path",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{String(getValue())}</span>
      ),
    },
    {
      accessorKey: "operationKind",
      header: "Operation",
      cell: ({ getValue }) => (
        <Badge variant="outline">{String(getValue())}</Badge>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ getValue }) => <StatusBadge value={getValue()} />,
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button
            onClick={() => setPanel({ mode: "inspect", row: row.original })}
            size="sm"
            variant="outline"
          >
            Inspect
          </Button>
          <Button
            disabled={row.original.status === "disabled"}
            onClick={() => setPanel({ mode: "edit", row: row.original })}
            size="sm"
            variant="outline"
          >
            Edit
          </Button>
          {row.original.status === "disabled" ? (
            <Button
              disabled={toggle.isPending}
              onClick={() =>
                toggle.mutate({ id: row.original.id, enable: true })
              }
              size="sm"
              variant="outline"
            >
              Enable
            </Button>
          ) : (
            <Button
              disabled={toggle.isPending}
              onClick={() => {
                if (window.confirm(`Disable "${row.original.name}"?`)) {
                  toggle.mutate({ id: row.original.id, enable: false });
                }
              }}
              size="sm"
              variant="destructive"
            >
              Disable
            </Button>
          )}
        </div>
      ),
    },
  ];

  const isPending = create.isPending || update.isPending;

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        limit={limit}
        noResultsMessage="No endpoints found."
        page={page}
        paramKey="endpoints"
        searchPlaceholder="Filter endpoints..."
        toolbar={
          <Button onClick={() => setPanel({ mode: "create" })}>
            <Plus data-icon="inline-start" />
            Create
          </Button>
        }
        total={total}
      />

      <Sheet
        open={panel?.mode === "create" || panel?.mode === "edit"}
        onOpenChange={(open) => {
          if (!open) setPanel(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          {panel?.mode === "create" || panel?.mode === "edit" ? (
            <>
              <SheetHeader>
                <SheetTitle>
                  {panel.mode === "create"
                    ? "Create endpoint"
                    : `Edit "${panel.row.name}"`}
                </SheetTitle>
                <SheetDescription>
                  Define the HTTP facade, GraphQL operation, auth mode, and
                  request/response JSON mappings.
                </SheetDescription>
              </SheetHeader>
              <div className="px-4 pb-4">
                <EndpointForm
                  defaultValues={panel.mode === "edit" ? panel.row : undefined}
                  isPending={isPending}
                  showPresets={panel.mode === "create"}
                  testEndpoint={panel.mode === "edit" ? panel.row : null}
                  onSubmit={(input) => {
                    if (panel.mode === "create") {
                      create.mutate(input);
                    } else {
                      update.mutate({ id: panel.row.id, input });
                    }
                  }}
                />
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>

      <Sheet
        open={panel?.mode === "inspect"}
        onOpenChange={(open) => {
          if (!open) setPanel(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          {panel?.mode === "inspect" ? (
            <>
              <SheetHeader>
                <SheetTitle>Inspect "{panel.row.name}"</SheetTitle>
                <SheetDescription>
                  Full endpoint configuration returned by the API.
                </SheetDescription>
              </SheetHeader>
              <div className="px-4 pb-4">
                <EndpointInspectDetails row={panel.row} />
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </>
  );
}

function EndpointForm({
  defaultValues,
  isPending,
  showPresets,
  testEndpoint,
  onSubmit,
}: {
  defaultValues?: ApiEndpointRow;
  isPending: boolean;
  showPresets?: boolean;
  testEndpoint: ApiEndpointRow | null;
  onSubmit: (input: EndpointInput) => void;
}) {
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: endpointFormValues(defaultValues),
  });

  function applyPreset(label: string) {
    const preset = ENDPOINT_PRESETS.find((p) => p.label === label);
    if (!preset) return;
    form.reset({ ...endpointFormValues(undefined), ...preset.values });
  }

  function submit(values: FormValues) {
    const input: EndpointInput = {};

    for (const key of [
      "key",
      "name",
      "description",
      "method",
      "path",
      "operationKind",
      "graphql",
      "authMode",
      "serviceEntityId",
      "status",
    ] as const) {
      const value = values[key].trim();
      if (value) input[key] = value;
    }

    for (const key of [
      "variablesMapping",
      "requestSchema",
      "responseMapping",
    ] as const) {
      input[key] = JSON.parse(values[key] || "{}") as unknown;
    }

    onSubmit(input);
  }

  return (
    <div className="mt-6 flex flex-col gap-4">
      {showPresets ? (
        <div className="flex flex-col gap-1">
          <div className="text-sm font-medium">Start from a template</div>
          <Select onValueChange={applyPreset}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Choose a template…" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {ENDPOINT_PRESETS.map((preset) => (
                  <SelectItem key={preset.label} value={preset.label}>
                    <span className="font-medium">{preset.label}</span>
                    <span className="ml-2 text-xs text-muted-foreground">
                      {preset.description}
                    </span>
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>
      ) : null}
      <Form {...form}>
        <form
          className="flex flex-col gap-4"
          onSubmit={form.handleSubmit(submit)}
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField
              control={form.control}
              name="key"
              render={({ field }) => (
                <FormItem>
                  <RequiredFormLabel required>Key</RequiredFormLabel>
                  <FormControl>
                    <Input placeholder="create_device" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <RequiredFormLabel required>Name</RequiredFormLabel>
                  <FormControl>
                    <Input placeholder="Create device" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Description</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid gap-4 sm:grid-cols-3">
            <EndpointSelectField
              control={form.control}
              label="Method"
              name="method"
              options={HTTP_METHODS}
            />
            <EndpointSelectField
              control={form.control}
              label="Operation"
              name="operationKind"
              options={OPERATION_KINDS}
            />
            <EndpointSelectField
              control={form.control}
              label="Status"
              name="status"
              options={STATUSES}
            />
          </div>

          <FormField
            control={form.control}
            name="path"
            render={({ field }) => (
              <FormItem>
                <RequiredFormLabel required>Path</RequiredFormLabel>
                <FormControl>
                  <Input placeholder="/api/custom/create-device" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid gap-4 sm:grid-cols-2">
            <EndpointSelectField
              control={form.control}
              label="Auth mode"
              name="authMode"
              options={AUTH_MODES}
            />
            <FormField
              control={form.control}
              name="serviceEntityId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Service entity ID</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Required for service_context"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="graphql"
            render={({ field }) => (
              <FormItem>
                <RequiredFormLabel required>
                  GraphQL operation
                </RequiredFormLabel>
                <FormControl>
                  <Textarea
                    className="min-h-44 font-mono text-xs"
                    placeholder="mutation CreateDevice($input: CreateResourceInput!) { createResource(input: $input) { id name } }"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <EndpointJsonField
            control={form.control}
            label="Variables mapping"
            name="variablesMapping"
          />
          <EndpointJsonField
            control={form.control}
            label="Request schema"
            name="requestSchema"
          />
          <EndpointJsonField
            control={form.control}
            label="Response mapping"
            name="responseMapping"
          />

          <Button disabled={isPending} type="submit">
            Save
          </Button>
        </form>
      </Form>

      {testEndpoint ? <EndpointTester endpoint={testEndpoint} /> : null}
    </div>
  );
}

function EndpointInspectDetails({ row }: { row: ApiEndpointRow }) {
  const createdByName = useEntityName(row.createdBy);
  const updatedByName = useEntityName(row.updatedBy);

  return (
    <div className="mt-6 flex flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <InspectField label="Name">
          <span className="text-sm">{row.name}</span>
        </InspectField>
        <InspectField label="Status">
          <StatusBadge value={row.status} />
        </InspectField>
      </div>

      <InspectField label="ID">
        <span className="break-all font-mono text-xs">{row.id}</span>
      </InspectField>

      <div className="grid gap-3 sm:grid-cols-2">
        <InspectField label="Key">
          <span className="font-mono text-xs">{row.key}</span>
        </InspectField>
        <InspectField label="Tenant">
          <span className="break-all font-mono text-xs">
            {row.tenantId ?? "Global"}
          </span>
        </InspectField>
      </div>

      {row.description ? (
        <InspectField label="Description">
          <span className="text-sm">{row.description}</span>
        </InspectField>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-3">
        <InspectField label="Method">
          <Badge variant="secondary">{row.method}</Badge>
        </InspectField>
        <InspectField label="Operation">
          <Badge variant="outline">{row.operationKind}</Badge>
        </InspectField>
        <InspectField label="Auth mode">
          <span className="font-mono text-xs">{row.authMode}</span>
        </InspectField>
      </div>

      <InspectField label="Path">
        <span className="break-all font-mono text-xs">{row.path}</span>
      </InspectField>

      {row.serviceEntityId ? (
        <InspectField label="Service entity ID">
          <span className="break-all font-mono text-xs">
            {row.serviceEntityId}
          </span>
        </InspectField>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
        <InspectField label="Created by">
          <ActorLabel id={row.createdBy} name={createdByName} />
        </InspectField>
        <InspectField label="Created at">
          <DisplayTimeCell action={Action.Created} time={row.createdAt} />
        </InspectField>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <InspectField label="Updated by">
          <ActorLabel id={row.updatedBy} name={updatedByName} />
        </InspectField>
        <InspectField label="Updated at">
          <DisplayTimeCell action={Action.Updated} time={row.updatedAt} />
        </InspectField>
      </div>

      <InspectField label="GraphQL operation">
        <GraphqlCodeEditor value={row.graphql} />
      </InspectField>

      <InspectField label="Variables mapping">
        <JsonEditor
          className="[&_.cm-editor]:min-h-28"
          value={stringifyJson(row.variablesMapping)}
        />
      </InspectField>

      <InspectField label="Request schema">
        <JsonEditor
          className="[&_.cm-editor]:min-h-28"
          value={stringifyJson(row.requestSchema)}
        />
      </InspectField>

      <InspectField label="Response mapping">
        <JsonEditor
          className="[&_.cm-editor]:min-h-28"
          value={stringifyJson(row.responseMapping)}
        />
      </InspectField>

      <EndpointTester endpoint={row} />
    </div>
  );
}

function useEntityName(id: string | null) {
  const query = useQuery({
    enabled: Boolean(id),
    queryKey: ["endpoint-inspect-actor", id],
    queryFn: ({ signal }) =>
      graphqlClient<{ entity: { id: string; name: string } }>({
        query: ENTITY_NAME_QUERY,
        variables: { id },
        signal,
      }),
    staleTime: 60_000,
  });

  return query.data?.entity.name ?? id ?? null;
}

function ActorLabel({ id, name }: { id: string | null; name: string | null }) {
  if (!id) {
    return <span className="text-sm text-muted-foreground">-</span>;
  }

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="truncate text-sm">{name ?? id}</span>
      {name && name !== id ? (
        <span className="break-all font-mono text-xs text-muted-foreground">
          {id}
        </span>
      ) : null}
    </div>
  );
}

function GraphqlCodeEditor({ value }: { value: string }) {
  const { resolvedTheme } = useTheme();

  return (
    <CodeMirror
      value={value}
      theme={resolvedTheme === "dark" ? "dark" : "light"}
      editable={false}
      readOnly
      extensions={CODE_EXTENSIONS}
      basicSetup={{
        foldGutter: true,
        lineNumbers: true,
        highlightActiveLine: false,
        highlightActiveLineGutter: false,
      }}
      className="max-w-full overflow-hidden rounded-md border bg-background text-xs [&_.cm-content]:max-w-full [&_.cm-editor]:min-h-40 [&_.cm-gutters]:border-r [&_.cm-line]:wrap-break-word [&_.cm-scroller]:font-mono"
    />
  );
}

function InspectField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border bg-background p-3">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}

type TestEndpointConfig = {
  method: string;
  path: string;
  requestSchema: unknown;
  variablesMapping: unknown;
  status?: string;
};
type TestField = {
  name: string;
  label: string;
  type: "string" | "number" | "boolean" | "json";
  source: "body" | "query";
  required: boolean;
};
type TestResult = {
  ok: boolean;
  status: number;
  body: unknown;
};

function EndpointTester({ endpoint }: { endpoint: TestEndpointConfig }) {
  const [rawBody, setRawBody] = React.useState("{}");
  const [result, setResult] = React.useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = React.useState(false);

  const requestSchema = React.useMemo(
    () => parseJsonLike(endpoint.requestSchema),
    [endpoint.requestSchema],
  );
  const variablesMapping = React.useMemo(
    () => parseJsonLike(endpoint.variablesMapping),
    [endpoint.variablesMapping],
  );
  const fields = React.useMemo(
    () => testFieldsFor(requestSchema, variablesMapping),
    [requestSchema, variablesMapping],
  );
  const formSchema = React.useMemo(
    () => z.object(testFieldShape(fields)),
    [fields],
  );
  const form = useForm<Record<string, string>>({
    resolver: zodResolver(formSchema),
    defaultValues: testFieldDefaults(fields),
  });

  React.useEffect(() => {
    form.reset(testFieldDefaults(fields));
  }, [form, fields]);

  async function runTest(values: Record<string, string>) {
    setResult(null);

    if (endpoint.status !== "active") {
      toast.error("Activate this endpoint before testing it.");
      return;
    }

    if (!endpoint.path.trim().startsWith("/api/custom/")) {
      toast.error("Endpoint path must start with /api/custom/.");
      return;
    }

    const url = new URL(endpoint.path.trim(), window.location.origin);
    const body = fields.length
      ? bodyFromTestFields(fields, values, url)
      : parseRawBody(rawBody);
    if (body instanceof Error) {
      toast.error(body.message);
      return;
    }

    setIsTesting(true);
    try {
      const method = endpoint.method.toUpperCase();
      const response = await fetch(url, {
        method,
        headers:
          method === "GET"
            ? { accept: "application/json" }
            : {
                accept: "application/json",
                "content-type": "application/json",
              },
        body: method === "GET" ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      const payload = parseResponseBody(text);
      setResult({ ok: response.ok, status: response.status, body: payload });
    } catch (err) {
      setResult({
        ok: false,
        status: 0,
        body: { error: err instanceof Error ? err.message : "Request failed" },
      });
    } finally {
      setIsTesting(false);
    }
  }

  return (
    <div className="flex flex-col gap-3 rounded-lg border bg-background p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs font-medium uppercase text-muted-foreground">
            Test endpoint
          </div>
          <div className="mt-1 font-mono text-xs text-muted-foreground">
            {endpoint.method || "GET"} {endpoint.path || "/api/custom/..."}
          </div>
        </div>
        {endpoint.status !== "active" ? (
          <Badge variant="outline">activate to test</Badge>
        ) : null}
      </div>

      {fields.length ? (
        <Form {...form}>
          <form
            className="flex flex-col gap-3"
            onSubmit={form.handleSubmit(runTest)}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              {fields.map((field) => (
                <FormField
                  control={form.control}
                  key={field.name}
                  name={field.name}
                  render={({ field: formField }) => (
                    <FormItem>
                      {field.required ? (
                        <RequiredFormLabel required>
                          {field.label}
                        </RequiredFormLabel>
                      ) : (
                        <FormLabel>{field.label}</FormLabel>
                      )}
                      <FormControl>
                        {field.type === "boolean" ? (
                          <Select
                            onValueChange={formField.onChange}
                            value={formField.value}
                          >
                            <SelectTrigger className="w-full">
                              <SelectValue placeholder="Choose value" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="true">true</SelectItem>
                                <SelectItem value="false">false</SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        ) : field.type === "json" ? (
                          <Textarea
                            className="min-h-24 font-mono text-xs"
                            placeholder="{}"
                            {...formField}
                          />
                        ) : (
                          <Input
                            placeholder={field.source}
                            type={field.type === "number" ? "number" : "text"}
                            {...formField}
                          />
                        )}
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ))}
            </div>
            <Button
              disabled={isTesting || endpoint.status !== "active"}
              type="submit"
              variant="outline"
            >
              Test endpoint
            </Button>
          </form>
        </Form>
      ) : (
        <div className="flex flex-col gap-3">
          <JsonEditor
            className="[&_.cm-editor]:min-h-28"
            onChange={setRawBody}
            value={rawBody}
          />
          <Button
            disabled={isTesting || endpoint.status !== "active"}
            onClick={() => void runTest({})}
            type="button"
            variant="outline"
          >
            Test endpoint
          </Button>
        </div>
      )}

      {result ? (
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <Badge variant={result.ok ? "default" : "destructive"}>
              {result.status || "error"}
            </Badge>
            <span className="text-sm text-muted-foreground">Response</span>
          </div>
          <JsonEditor
            className="[&_.cm-editor]:min-h-28"
            value={stringifyJson(result.body)}
          />
        </div>
      ) : null}
    </div>
  );
}

function EndpointSelectField({
  control,
  label,
  name,
  options,
}: {
  control: Control<FormValues>;
  label: string;
  name: "method" | "operationKind" | "authMode" | "status";
  options: string[];
}) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <Select onValueChange={field.onChange} value={field.value}>
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                {options.map((option) => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function EndpointJsonField({
  control,
  label,
  name,
}: {
  control: Control<FormValues>;
  label: string;
  name: "variablesMapping" | "requestSchema" | "responseMapping";
}) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <JsonEditor
              className="[&_.cm-editor]:min-h-28"
              onChange={field.onChange}
              value={field.value}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function endpointFormValues(defaultValues?: ApiEndpointRow): FormValues {
  return {
    key: defaultValues?.key ?? "",
    name: defaultValues?.name ?? "",
    description: defaultValues?.description ?? "",
    method: defaultValues?.method ?? "POST",
    path: defaultValues?.path ?? "/api/custom/",
    operationKind: defaultValues?.operationKind ?? "mutation",
    graphql: defaultValues?.graphql ?? "",
    authMode: defaultValues?.authMode ?? "caller_context",
    serviceEntityId: defaultValues?.serviceEntityId ?? "",
    variablesMapping: stringifyJson(defaultValues?.variablesMapping),
    requestSchema: stringifyJson(defaultValues?.requestSchema),
    responseMapping: stringifyJson(defaultValues?.responseMapping),
    status: defaultValues?.status ?? "draft",
  };
}

function isJsonObject(value: string) {
  try {
    JSON.parse(value || "{}");
    return true;
  } catch {
    return false;
  }
}

function parseJsonLike(value: unknown) {
  if (typeof value !== "string") {
    return value;
  }
  try {
    return JSON.parse(value || "{}") as unknown;
  } catch {
    return {};
  }
}

function testFieldsFor(schema: unknown, mapping: unknown): TestField[] {
  const schemaObject = asRecord(schema);
  const properties = asRecord(schemaObject?.properties);
  if (properties && Object.keys(properties).length > 0) {
    const required = Array.isArray(schemaObject?.required)
      ? new Set(schemaObject.required.map(String))
      : new Set<string>();
    return Object.entries(properties).map(([name, property]) => {
      const propertyObject = asRecord(property);
      return {
        name,
        label: name,
        type: testFieldType(propertyObject?.type),
        source: "body",
        required: required.has(name),
      };
    });
  }

  const mappingObject = asRecord(mapping);
  if (!mappingObject) {
    return [];
  }

  const fields: TestField[] = [];
  for (const source of Object.values(mappingObject)) {
    if (typeof source !== "string") {
      continue;
    }
    if (source.startsWith("$body.")) {
      const name = source.slice("$body.".length);
      fields.push({
        name,
        label: name,
        type: "string",
        source: "body",
        required: false,
      });
    }
    if (source.startsWith("$query.")) {
      const name = source.slice("$query.".length);
      fields.push({
        name,
        label: name,
        type: "string",
        source: "query",
        required: false,
      });
    }
  }

  return fields.filter(uniqueField);
}

function testFieldShape(fields: TestField[]) {
  return Object.fromEntries(
    fields.map((field) => {
      let validator = z.string();
      if (field.required) {
        validator = validator.trim().min(1, `${field.label} is required.`);
      }
      if (field.type === "number") {
        validator = validator.refine(
          (value) => !value || !Number.isNaN(Number(value)),
          "Must be a number.",
        );
      }
      if (field.type === "json") {
        validator = validator.refine(
          (value) => !value || isJsonObject(value),
          "Must be valid JSON.",
        );
      }
      return [field.name, validator];
    }),
  );
}

function testFieldDefaults(fields: TestField[]) {
  return Object.fromEntries(
    fields.map((field) => [field.name, field.type === "json" ? "{}" : ""]),
  );
}

function bodyFromTestFields(
  fields: TestField[],
  values: Record<string, string>,
  url: URL,
) {
  const body: Record<string, unknown> = {};
  for (const field of fields) {
    const raw = values[field.name];
    if (!raw && !field.required) {
      continue;
    }
    const value = coerceTestValue(field, raw);
    if (value instanceof Error) {
      return value;
    }
    if (field.source === "query") {
      url.searchParams.set(field.name, String(value));
    } else {
      setDottedBodyValue(body, field.name, value);
    }
  }
  return body;
}

function coerceTestValue(field: TestField, raw: string) {
  if (field.type === "number") {
    return Number(raw);
  }
  if (field.type === "boolean") {
    return raw === "true";
  }
  if (field.type === "json") {
    try {
      return JSON.parse(raw || "{}") as unknown;
    } catch {
      return new Error(`${field.label} must be valid JSON.`);
    }
  }
  return raw;
}

function parseRawBody(rawBody: string) {
  try {
    return JSON.parse(rawBody || "{}") as unknown;
  } catch {
    return new Error("Request body must be valid JSON.");
  }
}

function parseResponseBody(text: string) {
  try {
    return text ? (JSON.parse(text) as unknown) : {};
  } catch {
    return { text };
  }
}

function setDottedBodyValue(
  body: Record<string, unknown>,
  path: string,
  value: unknown,
) {
  const parts = path.split(".").filter(Boolean);
  let current = body;
  for (const part of parts.slice(0, -1)) {
    const next = current[part];
    if (!next || typeof next !== "object" || Array.isArray(next)) {
      current[part] = {};
    }
    current = current[part] as Record<string, unknown>;
  }
  current[parts[parts.length - 1] ?? path] = value;
}

function asRecord(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function testFieldType(value: unknown): TestField["type"] {
  if (value === "number" || value === "integer") {
    return "number";
  }
  if (value === "boolean") {
    return "boolean";
  }
  if (value === "object" || value === "array") {
    return "json";
  }
  return "string";
}

function uniqueField(field: TestField, index: number, fields: TestField[]) {
  return (
    fields.findIndex((candidate) => candidate.name === field.name) === index
  );
}

function stringifyJson(value: unknown) {
  if (value === undefined || value === null) {
    return "{}";
  }
  return JSON.stringify(value, null, 2);
}
