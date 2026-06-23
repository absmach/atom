"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  MinusCircle,
  Play,
  XCircle,
} from "lucide-react";
import * as React from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AsyncCombobox,
  type ComboOption,
  type ComboPage,
} from "@/components/ui/async-combobox";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { JsonEditor } from "@/components/ui/json-editor";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { ActionApplicability } from "@/lib/access/actions";
import {
  AUTHZ_TARGET_KINDS,
  type AuthzDebuggerInitialValues,
  type AuthzTargetKind,
} from "@/lib/authz/debugger-links";
import { graphqlClient } from "@/lib/graphql/client";

// ─── GraphQL ──────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

const ENTITIES_QUERY = `
  query AuthzEntities($q: String, $limit: Int, $offset: Int) {
    entities(q: $q, limit: $limit, offset: $offset) { items { id name kind } }
  }
`;
const ENTITY_QUERY = `
  query AuthzEntity($id: ID!) { entity(id: $id) { id name kind } }
`;
const TENANTS_QUERY = `
  query AuthzTenants($q: String, $limit: Int, $offset: Int) {
    tenants(q: $q, limit: $limit, offset: $offset) { items { id name } }
  }
`;
const CAPABILITIES_QUERY = `
  query AuthzActions($limit: Int, $offset: Int) {
    actions(limit: $limit, offset: $offset) { items { id name applicability { objectKind objectType } } }
  }
`;
const RESOURCES_QUERY = `
  query AuthzResources($q: String, $limit: Int, $offset: Int) {
    resources(q: $q, limit: $limit, offset: $offset) { items { id name kind } }
  }
`;
const RESOURCE_QUERY = `
  query AuthzResource($id: ID!) { resource(id: $id) { id name kind } }
`;
const OBJECT_GROUPS_QUERY = `
  query AuthzObjectGroups($q: String, $limit: Int, $offset: Int) {
    objectGroups(q: $q, limit: $limit, offset: $offset) { items { id name tenantId } }
  }
`;
const EXPLAIN_MUTATION = `
  mutation Explain($input: AuthzCheckInput!) {
    authzExplain(input: $input) {
      allowed
      reason
      matchedBinding
      evaluatedBindings
    }
  }
`;

// ─── Schema ───────────────────────────────────────────────────────────────────

const TARGET_KINDS = [
  {
    value: "platform",
    label: "Platform",
    description: "Global platform-level check. No target object is needed.",
  },
  {
    value: "tenant",
    label: "Tenant",
    description: "The tenant/domain object itself.",
  },
  {
    value: "entity",
    label: "Entity",
    description: "A human user, client/device, service, workload, or app.",
  },
  {
    value: "resource",
    label: "Resource",
    description: "A channel, rule, report, alarm, or other resource.",
  },
  {
    value: "group",
    label: "Object group",
    description: "The group object itself, not the objects inside it.",
  },
] as const;

const schema = z
  .object({
    subjectId: z.string().min(1, "Subject is required"),
    action: z.string().min(1, "Action is required"),
    targetKind: z.enum(AUTHZ_TARGET_KINDS),
    targetId: z.string().optional(),
    context: z.string(),
  })
  .superRefine((values, ctx) => {
    if (values.targetKind !== "platform" && !values.targetId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["targetId"],
        message: "Target is required",
      });
    }
  });
type FormValues = z.infer<typeof schema>;

type ExplainResponse = {
  authzExplain: {
    allowed: boolean;
    reason: string;
    matchedBinding?: Record<string, unknown> | null;
    evaluatedBindings: Array<Record<string, unknown>>;
  };
};

// ─── Lazy option fetchers ───────────────────────────────────────────────────

function pageOf(items: ComboOption[], offset: number): ComboPage {
  return {
    items,
    nextOffset: items.length === PAGE_SIZE ? offset + PAGE_SIZE : null,
  };
}

async function fetchEntities({
  search,
  offset,
  signal,
}: FetchPageArgs): Promise<ComboPage> {
  const data = await graphqlClient<{ entities: { items: EntityOption[] } }>({
    query: ENTITIES_QUERY,
    variables: { q: search || null, limit: PAGE_SIZE, offset },
    signal,
  });
  return pageOf(
    data.entities.items.map((e) => ({
      value: e.id,
      label: e.name,
      detail: e.kind,
    })),
    offset,
  );
}

async function fetchTenants({
  search,
  offset,
  signal,
}: FetchPageArgs): Promise<ComboPage> {
  const data = await graphqlClient<{ tenants: { items: TenantOption[] } }>({
    query: TENANTS_QUERY,
    variables: { q: search || null, limit: PAGE_SIZE, offset },
    signal,
  });
  return pageOf(
    data.tenants.items.map((t) => ({ value: t.id, label: t.name })),
    offset,
  );
}

async function fetchResources({
  search,
  offset,
  signal,
}: FetchPageArgs): Promise<ComboPage> {
  const data = await graphqlClient<{ resources: { items: ResourceOption[] } }>({
    query: RESOURCES_QUERY,
    variables: { q: search || null, limit: PAGE_SIZE, offset },
    signal,
  });
  return pageOf(
    data.resources.items.map((r) => ({
      value: r.id,
      label: r.name,
      detail: r.kind,
    })),
    offset,
  );
}

async function fetchObjectGroups({
  search,
  offset,
  signal,
}: FetchPageArgs): Promise<ComboPage> {
  const data = await graphqlClient<{ objectGroups: { items: GroupOption[] } }>({
    query: OBJECT_GROUPS_QUERY,
    variables: { q: search || null, limit: PAGE_SIZE, offset },
    signal,
  });
  return pageOf(
    data.objectGroups.items.map((g) => ({
      value: g.id,
      label: g.name,
      detail: g.tenantId ? `tenant ${g.tenantId.slice(0, 8)}…` : undefined,
    })),
    offset,
  );
}

const emptyFetchPage = async (): Promise<ComboPage> => ({
  items: [],
  nextOffset: null,
});

async function fetchSelectedEntity({
  value,
  signal,
}: FetchSelectedArgs): Promise<ComboOption | null> {
  const data = await graphqlClient<{ entity: EntityOption | null }>({
    query: ENTITY_QUERY,
    variables: { id: value },
    signal,
  });
  return data.entity
    ? {
        value: data.entity.id,
        label: data.entity.name,
        detail: data.entity.kind,
      }
    : null;
}

async function fetchSelectedResource({
  value,
  signal,
}: FetchSelectedArgs): Promise<ComboOption | null> {
  const data = await graphqlClient<{ resource: ResourceOption | null }>({
    query: RESOURCE_QUERY,
    variables: { id: value },
    signal,
  });
  return data.resource
    ? {
        value: data.resource.id,
        label: data.resource.name,
        detail: data.resource.kind,
      }
    : null;
}

type FetchPageArgs = { search: string; offset: number; signal?: AbortSignal };
type FetchSelectedArgs = { value: string; signal?: AbortSignal };

type TargetFetcher = {
  fetchPage: (args: FetchPageArgs) => Promise<ComboPage>;
  fetchSelected?: (args: FetchSelectedArgs) => Promise<ComboOption | null>;
};

const TARGET_FETCHERS: Partial<Record<AuthzTargetKind, TargetFetcher>> = {
  tenant: { fetchPage: fetchTenants },
  entity: { fetchPage: fetchEntities, fetchSelected: fetchSelectedEntity },
  resource: {
    fetchPage: fetchResources,
    fetchSelected: fetchSelectedResource,
  },
  group: { fetchPage: fetchObjectGroups },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function AuthzDebugger({
  initialValues = {},
}: {
  initialValues?: AuthzDebuggerInitialValues;
}) {
  // Actions are a bounded canonical set and are also needed to resolve grant
  // names in the result trace, so they are loaded once rather than lazily.
  const actionsQ = useQuery({
    queryKey: ["authz-actions"],
    queryFn: ({ signal }) =>
      graphqlClient<{ actions: { items: ActionItem[] } }>({
        query: CAPABILITIES_QUERY,
        variables: { limit: 200, offset: 0 },
        signal,
      }),
    staleTime: 60_000,
  });
  const actions = actionsQ.data?.actions.items ?? [];
  const actionOptions = React.useMemo<ComboOption[]>(
    () => actions.map((a) => ({ value: a.id, label: a.name })),
    [actions],
  );
  const fetchActionPage = React.useCallback(
    async (): Promise<ComboPage> => ({
      items: actionOptions,
      nextOffset: null,
    }),
    [actionOptions],
  );

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      subjectId: initialValues.subjectId ?? "",
      action: "",
      targetKind: initialValues.targetKind ?? "resource",
      targetId: initialValues.targetId ?? "",
      context: "{}",
    },
  });

  const targetKind = form.watch("targetKind");
  const targetFetcher = TARGET_FETCHERS[targetKind];
  const targetKindMeta = TARGET_KINDS.find((item) => item.value === targetKind);

  const [selectedSubject, setSelectedSubject] =
    React.useState<ComboOption | null>(null);
  const [selectedTarget, setSelectedTarget] =
    React.useState<ComboOption | null>(null);
  const selectedAction = actions.find(
    (action) => action.id === form.watch("action"),
  );

  const explain = useMutation({
    mutationFn: (values: FormValues) => {
      const action = actions.find((item) => item.id === values.action);
      const context = parseContext(values.context);
      return graphqlClient<ExplainResponse>({
        query: EXPLAIN_MUTATION,
        variables: {
          input: buildAuthzInput({
            subjectId: values.subjectId,
            action: action?.name ?? values.action,
            targetKind: values.targetKind,
            targetId: values.targetId,
            context,
          }),
        },
      });
    },
  });

  const result = explain.data?.authzExplain;

  return (
    <div className="grid gap-4 xl:grid-cols-[460px_1fr]">
      {/* ── Input form ── */}
      <Card>
        <CardHeader>
          <CardTitle>Authorization request</CardTitle>
          <CardDescription>
            Read this as: who wants to do what on which target.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form
              className="grid gap-4"
              onSubmit={form.handleSubmit((v) => explain.mutate(v))}
            >
              <FormField
                control={form.control}
                name="subjectId"
                render={({ field }) => (
                  <FormItem>
                    <RequiredFormLabel required>Who</RequiredFormLabel>
                    <FormControl>
                      <AsyncCombobox
                        value={field.value}
                        onChange={field.onChange}
                        onSelectedChange={setSelectedSubject}
                        queryKey={["authz-entities"]}
                        fetchPage={fetchEntities}
                        fetchSelected={fetchSelectedEntity}
                        placeholder="Select subject"
                        searchPlaceholder="Search entities…"
                        emptyText="No entities found."
                      />
                    </FormControl>
                    <FormDescription>
                      The entity making the request, for example a user, client,
                      or service.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="action"
                render={({ field }) => (
                  <FormItem>
                    <RequiredFormLabel required>Can do</RequiredFormLabel>
                    <FormControl>
                      <AsyncCombobox
                        value={field.value}
                        onChange={field.onChange}
                        queryKey={[
                          "authz-actions",
                          "combo",
                          actionOptions.length,
                        ]}
                        mode="client"
                        fetchPage={fetchActionPage}
                        placeholder="Select action"
                        searchPlaceholder="Search actions…"
                        emptyText="No actions found."
                      />
                    </FormControl>
                    <FormDescription>
                      Action names are the canonical Atom permissions, such as
                      read, write, publish, role.manage, or policy.manage.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="targetKind"
                render={({ field }) => (
                  <FormItem>
                    <RequiredFormLabel required>Target type</RequiredFormLabel>
                    <Select
                      value={field.value}
                      onValueChange={(v) => {
                        const next = v as AuthzTargetKind;
                        field.onChange(next);
                        form.setValue("targetId", "");
                      }}
                    >
                      <FormControl>
                        <SelectTrigger className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {TARGET_KINDS.map((kind) => (
                          <SelectItem key={kind.value} value={kind.value}>
                            {kind.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormDescription>
                      {targetKindMeta?.description}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {targetKind !== "platform" && (
                <FormField
                  control={form.control}
                  name="targetId"
                  render={({ field }) => (
                    <FormItem>
                      <RequiredFormLabel required>
                        {targetKindMeta?.label ?? "Target"}
                      </RequiredFormLabel>
                      <FormControl>
                        <AsyncCombobox
                          key={targetKind}
                          value={field.value ?? ""}
                          onChange={field.onChange}
                          onSelectedChange={setSelectedTarget}
                          queryKey={["authz-target", targetKind]}
                          fetchPage={targetFetcher?.fetchPage ?? emptyFetchPage}
                          fetchSelected={targetFetcher?.fetchSelected}
                          placeholder="Select target"
                          searchPlaceholder={`Search ${targetKindMeta?.label.toLowerCase() ?? "targets"}…`}
                          emptyText="No targets found."
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}

              <div className="rounded-lg border bg-muted/30 p-3 text-sm">
                <div className="mb-1 text-xs font-medium uppercase text-muted-foreground">
                  Request preview
                </div>
                <div>
                  <span className="font-medium">
                    {selectedSubject?.label ?? "Selected subject"}
                  </span>{" "}
                  wants to{" "}
                  <span className="font-medium">
                    {selectedAction?.name ?? "selected action"}
                  </span>{" "}
                  on{" "}
                  <span className="font-medium">
                    {targetKind === "platform"
                      ? "the platform"
                      : (selectedTarget?.label ?? "selected target")}
                  </span>
                  .
                </div>
              </div>

              <FormField
                control={form.control}
                name="context"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Optional context JSON</FormLabel>
                    <FormControl>
                      <JsonEditor
                        value={field.value}
                        onChange={field.onChange}
                        className="[&_.cm-editor]:min-h-16"
                      />
                    </FormControl>
                    <FormDescription>
                      Extra request attributes used by conditional permissions.
                      Keep <code>{"{}"}</code> for a normal check.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button
                type="submit"
                disabled={explain.isPending}
                className="w-full"
              >
                <Play className="size-4" />
                Explain decision
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>

      {/* ── Results ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {result?.allowed ? (
              <CheckCircle2 className="text-primary" />
            ) : result ? (
              <XCircle className="text-destructive" />
            ) : (
              <AlertTriangle className="text-muted-foreground" />
            )}
            Decision
          </CardTitle>
          <CardDescription>
            Atom checks direct policies and role assignments, then applies
            deny-overrides-allow.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          {explain.isError ? (
            <Alert variant="destructive">
              <AlertTriangle className="size-4" />
              <AlertTitle>Explain failed</AlertTitle>
              <AlertDescription>{explain.error.message}</AlertDescription>
            </Alert>
          ) : null}

          {result ? (
            <>
              <div className="rounded-lg border p-4">
                <Badge variant={result.allowed ? "default" : "destructive"}>
                  {result.allowed ? "Allowed" : "Denied"}
                </Badge>
                <p className="mt-3 text-lg">{result.reason}</p>
              </div>
              <TraceList
                title="Matched permission"
                items={result.matchedBinding ? [result.matchedBinding] : []}
                actions={actions}
              />
              <TraceList
                title="Permissions checked"
                items={result.evaluatedBindings ?? []}
                actions={actions}
              />
            </>
          ) : (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Choose who, action, and target to see the decision.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Trace display ────────────────────────────────────────────────────────────

type ActionItem = {
  id: string;
  name: string;
  applicability: ActionApplicability[];
};

type EntityOption = { id: string; name: string; kind: string };
type TenantOption = { id: string; name: string };
type ResourceOption = { id: string; name: string; kind: string };
type GroupOption = { id: string; name: string; tenantId?: string | null };

function parseContext(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value || "{}") as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
      throw new Error("Context must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "Context must be a JSON object"
    ) {
      throw error;
    }
    throw new Error("Context must be valid JSON");
  }
}

function buildAuthzInput(values: {
  subjectId: string;
  action: string;
  targetKind: AuthzTargetKind;
  targetId?: string;
  context: Record<string, unknown>;
}) {
  const input: Record<string, unknown> = {
    subjectId: values.subjectId,
    action: values.action,
    context: values.context,
  };

  if (values.targetKind === "platform") {
    input.objectKind = "platform";
    return input;
  }

  input.objectKind = values.targetKind;
  input.objectId = values.targetId;
  return input;
}

function authzScopeSummary(kind: string, ref?: string) {
  switch (kind) {
    case "platform":
      return "entire platform";
    case "tenant":
      return ref ? `tenant ${ref}` : "tenant";
    case "object_kind":
      return ref ? `all ${ref} objects` : "all objects of a kind";
    case "object_type":
      return ref ? `all ${ref}` : "all objects of a type";
    case "object":
      return ref ? `exact object ${ref}` : "exact object";
    case "group":
      return ref ? `object group ${ref}` : "object group";
    case "group_direct_objects":
      return ref ? `direct objects in group ${ref}` : "direct group objects";
    case "group_descendant_objects":
      return ref ? `objects in subgroups of ${ref}` : "objects in subgroups";
    case "group_child_groups":
      return ref ? `direct child groups of ${ref}` : "direct child groups";
    case "group_descendant_groups":
      return ref ? `descendant groups of ${ref}` : "descendant groups";
    default:
      return ref ? `${kind} ${ref}` : kind;
  }
}

const SKIP_REASON_LABELS: Record<string, string> = {
  scope_mismatch: "Permission scope does not cover this target",
  grant_mismatch: "Action not covered by this grant",
  conditions_mismatch: "ABAC conditions not satisfied",
};

function TraceList({
  title,
  items,
  actions,
}: {
  title: string;
  items: Array<Record<string, unknown>>;
  actions: ActionItem[];
}) {
  return (
    <div className="grid gap-2">
      <div className="text-sm font-medium">{title}</div>
      {items.length ? (
        items.map((item) => (
          <TraceCard
            key={`${title}-${String(item.id ?? item.scope_ref ?? JSON.stringify(item))}`}
            item={item}
            actions={actions}
          />
        ))
      ) : (
        <div className="rounded-lg border border-dashed p-3 text-sm text-muted-foreground">
          No permissions returned.
        </div>
      )}
    </div>
  );
}

function TraceCard({
  item,
  actions,
}: {
  item: Record<string, unknown>;
  actions: ActionItem[];
}) {
  const effect = String(item.effect ?? "allow");
  const result = String(item.result ?? "skipped");
  const via = String(item.via ?? "direct");
  const rawGrantKind = String(item.grant_kind ?? "action");
  const grantKind = rawGrantKind === "capability" ? "action" : rawGrantKind;
  const grantId = item.grant_id ? String(item.grant_id) : null;
  const roleName = item.role_name ? String(item.role_name) : null;
  const scopeKind = String(item.scope_kind ?? "platform");
  const scopeRef = item.scope_ref ? String(item.scope_ref) : undefined;
  const skipReason = item.skip_reason ? String(item.skip_reason) : null;

  const capName = grantId
    ? (actions.find((c) => c.id === grantId)?.name ?? null)
    : null;
  const grantLabel =
    grantKind === "role"
      ? (roleName ?? (grantId ? `${grantId.slice(0, 8)}…` : "unknown role"))
      : (capName ?? (grantId ? `${grantId.slice(0, 8)}…` : "unknown action"));

  const viaLabel = via.startsWith("group:")
    ? `Inherited through principal group "${via.slice(6)}"`
    : "Direct assignment or policy";

  const isMatched = result === "matched";
  const isDeny = effect === "deny";

  const accentClass = isMatched
    ? isDeny
      ? "border-l-destructive"
      : "border-l-primary"
    : "border-l-muted-foreground/30";

  const headline = isMatched
    ? isDeny
      ? "This permission denies the request"
      : "This permission allows the request"
    : `Skipped — ${SKIP_REASON_LABELS[skipReason ?? ""] ?? skipReason ?? "not applicable"}`;

  const HeadlineIcon = isMatched
    ? isDeny
      ? XCircle
      : CheckCircle2
    : MinusCircle;

  const iconClass = isMatched
    ? isDeny
      ? "text-destructive"
      : "text-primary"
    : "text-muted-foreground";

  const rows: Array<{ label: string; value: string; mono?: boolean }> = [
    {
      label: "Effect",
      value: effect === "allow" ? "Allow" : "Deny",
    },
    {
      label: grantKind === "role" ? "Role" : "Action",
      value: grantLabel,
    },
    {
      label: "Applies to",
      value: authzScopeSummary(scopeKind, scopeRef),
    },
    {
      label: "Via",
      value: viaLabel,
    },
  ];

  return (
    <div
      className={`grid gap-3 rounded-lg border border-l-4 p-3 text-sm ${accentClass}`}
    >
      <div className={`flex items-center gap-2 font-medium ${iconClass}`}>
        <HeadlineIcon className="size-4 shrink-0" />
        {headline}
      </div>
      <div className="grid gap-1.5">
        {rows.map(({ label, value, mono }) => (
          <div key={label} className="flex gap-3">
            <span className="w-24 shrink-0 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {label}
            </span>
            <span className={`text-xs ${mono ? "font-mono" : ""}`}>
              {value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
