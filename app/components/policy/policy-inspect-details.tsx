"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import {
  EffectBadge,
  GrantKindBadge,
  PolicySummary,
  ScopeKindBadge,
  SubjectKindBadge,
  type ScopeKind,
} from "@/components/policy/policy-summary";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { graphqlClient } from "@/lib/graphql/client";
import { scopeSummary } from "@/lib/policy/summary";
import { Action } from "@/lib/utils";

const ENTITY_QUERY = `query PolicyInspectEntity($id: ID!) { entity(id: $id) { id name kind } }`;
const GROUP_QUERY = `query PolicyInspectGroup($id: ID!) { group(id: $id) { id name } }`;
const CAPABILITY_QUERY = `query PolicyInspectCapability($id: ID!) { capability(id: $id) { id name resourceKind } }`;
const ROLE_QUERY = `query PolicyInspectRole($id: ID!) { role(id: $id) { id name } }`;

type Row = Record<string, unknown>;

export function PolicyInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);

  const id = String(row?.id ?? "");
  const subjectKind = String(row?.subjectKind ?? "");
  const subjectId = String(row?.subjectId ?? "");
  const grantKind = String(row?.grantKind ?? "");
  const grantId = String(row?.grantId ?? "");
  const scopeKind = String(row?.scopeKind ?? "platform") as ScopeKind;
  const scopeRef = row?.scopeRef ? String(row.scopeRef) : undefined;
  const effect = String(row?.effect ?? "allow") as "allow" | "deny";
  const conditions = parseConditions(row?.conditions);

  const entityQ = useQuery({
    enabled: subjectKind === "entity" && Boolean(subjectId),
    queryKey: ["policy-inspect-entity", subjectId],
    queryFn: ({ signal }) =>
      graphqlClient<{ entity: { id: string; name: string; kind: string } }>({
        query: ENTITY_QUERY,
        variables: { id: subjectId },
        signal,
      }),
    staleTime: 60_000,
  });
  const groupQ = useQuery({
    enabled: subjectKind === "group" && Boolean(subjectId),
    queryKey: ["policy-inspect-group", subjectId],
    queryFn: ({ signal }) =>
      graphqlClient<{ group: { id: string; name: string } }>({
        query: GROUP_QUERY,
        variables: { id: subjectId },
        signal,
      }),
    staleTime: 60_000,
  });
  const capabilityQ = useQuery({
    enabled: grantKind === "capability" && Boolean(grantId),
    queryKey: ["policy-inspect-capability", grantId],
    queryFn: ({ signal }) =>
      graphqlClient<{
        capability: { id: string; name: string; resourceKind: string | null };
      }>({
        query: CAPABILITY_QUERY,
        variables: { id: grantId },
        signal,
      }),
    staleTime: 60_000,
  });
  const roleQ = useQuery({
    enabled: grantKind === "role" && Boolean(grantId),
    queryKey: ["policy-inspect-role", grantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ role: { id: string; name: string } }>({
        query: ROLE_QUERY,
        variables: { id: grantId },
        signal,
      }),
    staleTime: 60_000,
  });

  const entity = entityQ.data?.entity;
  const group = groupQ.data?.group;
  const capability = capabilityQ.data?.capability;
  const role = roleQ.data?.role;

  const subjectName =
    entity?.name ?? group?.name ?? subjectId.slice(0, 8) + "…";
  const grantName = capability?.name ?? role?.name ?? grantId.slice(0, 8) + "…";
  const grantLabel = capability
    ? `${capability.name}${capability.resourceKind ? ` · ${capability.resourceKind}` : ""}`
    : grantName;

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  return (
    <div className="grid gap-4">
      {/* Summary */}
      <div className="rounded-lg border bg-muted/30 p-4">
        <div className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Summary
        </div>
        <PolicySummary
          effect={effect}
          subjectKind={subjectKind}
          subjectName={subjectName}
          grantKind={grantKind}
          grantLabel={grantLabel}
          scopeKind={scopeKind}
          scopeRef={scopeRef}
          conditions={conditions}
        />
      </div>

      {/* Details */}
      <div className="grid gap-3">
        <Field label="ID">
          <div className="flex items-center gap-2">
            <span className="break-all font-mono text-xs">{id}</span>
            <Button
              className="h-6 w-6 shrink-0"
              onClick={copyId}
              size="icon"
              variant="ghost"
            >
              {copied ? (
                <Check className="size-3.5" />
              ) : (
                <Copy className="size-3.5" />
              )}
            </Button>
          </div>
        </Field>

        <Field label="Effect">
          <EffectBadge effect={effect} />
        </Field>

        <Field label="Subject">
          <div className="flex flex-wrap items-center gap-2">
            <SubjectKindBadge kind={subjectKind} />
            <span className="text-sm">
              {entity
                ? `${entity.name} (${entity.kind})`
                : group
                  ? group.name
                  : subjectId}
            </span>
          </div>
        </Field>

        <Field label="Grant">
          <div className="flex flex-wrap items-center gap-2">
            <GrantKindBadge kind={grantKind} />
            <span className="text-sm">
              {capability
                ? `${capability.name}${capability.resourceKind ? ` · ${capability.resourceKind}` : ""}`
                : role
                  ? role.name
                  : grantId}
            </span>
          </div>
        </Field>

        <Field label="Scope">
          <div className="flex flex-wrap items-center gap-2">
            <ScopeKindBadge kind={scopeKind} />
            {scopeRef ? (
              <span className="font-mono text-xs">{scopeRef}</span>
            ) : (
              <span className="text-sm">
                {scopeSummary(scopeKind, scopeRef)}
              </span>
            )}
          </div>
        </Field>

        {conditions.length > 0 ? (
          <Field label="Conditions">
            <div className="flex flex-wrap gap-2">
              {conditions.map((c, i) => (
                <Badge
                  key={`${c.path}-${i}`}
                  className="font-mono text-xs"
                  variant="outline"
                >
                  {c.path} = {c.value}
                </Badge>
              ))}
            </div>
          </Field>
        ) : null}

        {row.createdAt ? (
          <Field label="Created">
            <DisplayTimeCell
              action={Action.Created}
              time={String(row.createdAt)}
            />
          </Field>
        ) : null}
      </div>
    </div>
  );
}

// ─── Field ────────────────────────────────────────────────────────────────────

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 rounded-lg border bg-background p-3">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseConditions(
  raw: unknown,
): Array<{ path: string; operator: "equals"; value: string }> {
  if (!raw) return [];
  try {
    const arr = Array.isArray(raw) ? raw : JSON.parse(String(raw));
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((c) => c && typeof c === "object")
      .map((c: Record<string, string>) => ({
        path: String(c.path ?? ""),
        operator: "equals" as const,
        value: String(c.value ?? ""),
      }));
  } catch {
    return [];
  }
}
