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
import { useForm } from "react-hook-form";
import { z } from "zod";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Switch } from "@/components/ui/switch";
import { graphqlClient } from "@/lib/graphql/client";
import { scopeSummary } from "@/lib/policy/summary";

// ─── GraphQL ──────────────────────────────────────────────────────────────────

const ENTITIES_QUERY = `
  query AuthzEntities { entities(limit: 200, offset: 0) { items { id name kind } } }
`;
const CAPABILITIES_QUERY = `
  query AuthzCapabilities { capabilities(limit: 200, offset: 0) { items { id name resourceKind } } }
`;
const RESOURCES_QUERY = `
  query AuthzResources { resources(limit: 200, offset: 0) { items { id name kind } } }
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

const NONE = "__none__";

const schema = z.object({
  subjectId: z.string().min(1, "Subject is required"),
  action: z.string().min(1, "Action is required"),
  platformCheck: z.boolean(),
  resourceId: z.string().optional(),
  context: z.string(),
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

// ─── Component ────────────────────────────────────────────────────────────────

export function AuthzDebugger() {
  const entitiesQ = useQuery({
    queryKey: ["authz-entities"],
    queryFn: ({ signal }) =>
      graphqlClient<{
        entities: { items: { id: string; name: string; kind: string }[] };
      }>({
        query: ENTITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const capsQ = useQuery({
    queryKey: ["authz-capabilities"],
    queryFn: ({ signal }) =>
      graphqlClient<{
        capabilities: {
          items: { id: string; name: string; resourceKind: string | null }[];
        };
      }>({
        query: CAPABILITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const resourcesQ = useQuery({
    queryKey: ["authz-resources"],
    queryFn: ({ signal }) =>
      graphqlClient<{
        resources: { items: { id: string; name: string; kind: string }[] };
      }>({
        query: RESOURCES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const entities = entitiesQ.data?.entities.items ?? [];
  const capabilities = capsQ.data?.capabilities.items ?? [];
  const resources = resourcesQ.data?.resources.items ?? [];

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      subjectId: "",
      action: "",
      platformCheck: false,
      resourceId: "",
      context: "{}",
    },
  });

  const platformCheck = form.watch("platformCheck");

  const explain = useMutation({
    mutationFn: (values: FormValues) => {
      const selectedCapability = capabilities.find(
        (c) => c.id === values.action,
      );
      let context: Record<string, unknown> = {};
      try {
        context = JSON.parse(values.context || "{}") as Record<string, unknown>;
      } catch {
        // fall back to empty context
      }
      const resourceId =
        !values.platformCheck && values.resourceId && values.resourceId !== NONE
          ? values.resourceId
          : null;
      return graphqlClient<ExplainResponse>({
        query: EXPLAIN_MUTATION,
        variables: {
          input: {
            subjectId: values.subjectId,
            action: selectedCapability?.name ?? values.action,
            resourceId,
            objectKind: values.platformCheck ? "platform" : undefined,
            context,
          },
        },
      });
    },
  });

  const result = explain.data?.authzExplain;

  return (
    <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
      {/* ── Input form ── */}
      <Card>
        <CardHeader>
          <CardTitle>Check request</CardTitle>
          <CardDescription>
            Ask Atom why an action is allowed or denied.
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
                    <RequiredFormLabel required>
                      Subject entity
                    </RequiredFormLabel>
                    <Select
                      value={field.value || NONE}
                      onValueChange={(v) => field.onChange(v === NONE ? "" : v)}
                    >
                      <FormControl>
                        <SelectTrigger className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value={NONE}>— select entity —</SelectItem>
                        {entities.map((e) => (
                          <SelectItem key={e.id} value={e.id}>
                            {e.name}
                            <span className="ml-1.5 text-xs text-muted-foreground">
                              {e.kind}
                            </span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="action"
                render={({ field }) => (
                  <FormItem>
                    <RequiredFormLabel required>Action</RequiredFormLabel>
                    <Select
                      value={field.value || NONE}
                      onValueChange={(v) => field.onChange(v === NONE ? "" : v)}
                    >
                      <FormControl>
                        <SelectTrigger className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value={NONE}>
                          — select capability —
                        </SelectItem>
                        {capabilities.map((c) => (
                          <SelectItem key={c.id} value={c.id}>
                            {c.name}
                            {c.resourceKind ? (
                              <span className="ml-1.5 text-xs text-muted-foreground">
                                {c.resourceKind}
                              </span>
                            ) : null}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="platformCheck"
                render={({ field }) => (
                  <FormItem className="flex items-center justify-between rounded-lg border p-3">
                    <div>
                      <FormLabel>Platform-scoped check</FormLabel>
                      <FormDescription className="text-xs">
                        Check against the entire platform, no resource needed.
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />

              {!platformCheck && (
                <FormField
                  control={form.control}
                  name="resourceId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Resource</FormLabel>
                      <Select
                        value={field.value || NONE}
                        onValueChange={(v) =>
                          field.onChange(v === NONE ? "" : v)
                        }
                      >
                        <FormControl>
                          <SelectTrigger className="w-full">
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value={NONE}>
                            — select resource —
                          </SelectItem>
                          {resources.map((r) => (
                            <SelectItem key={r.id} value={r.id}>
                              {r.name}
                              <span className="ml-1.5 text-xs text-muted-foreground">
                                {r.kind}
                              </span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}

              <FormField
                control={form.control}
                name="context"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Context JSON</FormLabel>
                    <FormControl>
                      <JsonEditor
                        value={field.value}
                        onChange={field.onChange}
                        className="[&_.cm-editor]:min-h-16"
                      />
                    </FormControl>
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
                Run explain
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
            Decision trace
          </CardTitle>
          <CardDescription>
            DENY precedence, ABAC conditions, role expansion, and group-derived
            permissions surface here when returned by the service.
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
                title="Matched policy"
                items={result.matchedBinding ? [result.matchedBinding] : []}
                capabilities={capabilities}
              />
              <TraceList
                title="Evaluated bindings"
                items={result.evaluatedBindings ?? []}
                capabilities={capabilities}
              />
            </>
          ) : (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Run a check to see the policy trace.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Trace display ────────────────────────────────────────────────────────────

type CapabilityItem = { id: string; name: string; resourceKind: string | null };

const SKIP_REASON_LABELS: Record<string, string> = {
  scope_mismatch: "Scope doesn't cover this resource",
  grant_mismatch: "Action not covered by this grant",
  conditions_mismatch: "ABAC conditions not satisfied",
};

function TraceList({
  title,
  items,
  capabilities,
}: {
  title: string;
  items: Array<Record<string, unknown>>;
  capabilities: CapabilityItem[];
}) {
  return (
    <div className="grid gap-2">
      <div className="text-sm font-medium">{title}</div>
      {items.length ? (
        items.map((item) => (
          <TraceCard
            key={`${title}-${String(item.id ?? item.scope_ref ?? JSON.stringify(item))}`}
            item={item}
            capabilities={capabilities}
          />
        ))
      ) : (
        <div className="rounded-lg border border-dashed p-3 text-sm text-muted-foreground">
          No bindings returned.
        </div>
      )}
    </div>
  );
}

function TraceCard({
  item,
  capabilities,
}: {
  item: Record<string, unknown>;
  capabilities: CapabilityItem[];
}) {
  const effect = String(item.effect ?? "allow");
  const result = String(item.result ?? "skipped");
  const via = String(item.via ?? "direct");
  const grantKind = String(item.grant_kind ?? "capability");
  const grantId = item.grant_id ? String(item.grant_id) : null;
  const roleName = item.role_name ? String(item.role_name) : null;
  const scopeKind = String(item.scope_kind ?? "platform") as Parameters<
    typeof scopeSummary
  >[0];
  const scopeRef = item.scope_ref ? String(item.scope_ref) : undefined;
  const skipReason = item.skip_reason ? String(item.skip_reason) : null;

  const capName = grantId
    ? (capabilities.find((c) => c.id === grantId)?.name ?? null)
    : null;
  const grantLabel =
    grantKind === "role"
      ? (roleName ?? (grantId ? `${grantId.slice(0, 8)}…` : "unknown role"))
      : (capName ??
        (grantId ? `${grantId.slice(0, 8)}…` : "unknown capability"));

  const viaLabel = via.startsWith("group:")
    ? `Inherited via group "${via.slice(6)}"`
    : "Direct binding";

  const isMatched = result === "matched";
  const isDeny = effect === "deny";

  const accentClass = isMatched
    ? isDeny
      ? "border-l-destructive"
      : "border-l-primary"
    : "border-l-muted-foreground/30";

  const headline = isMatched
    ? isDeny
      ? "This binding will deny the request"
      : "This binding allows the request"
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
      label: grantKind === "role" ? "Role" : "Capability",
      value: grantLabel,
    },
    {
      label: "Scope",
      value: scopeSummary(scopeKind, scopeRef),
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
