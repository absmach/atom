"use client";

import { useQuery } from "@tanstack/react-query";
import { graphqlClient } from "@/lib/graphql/client";
import { summarizePolicy, scopeSummary } from "@/lib/policy/summary";

const ENTITY_QUERY = `query PolicyInspectEntity($id: ID!) { entity(id: $id) { id name kind } }`;
const GROUP_QUERY = `query PolicyInspectGroup($id: ID!) { group(id: $id) { id name } }`;
const CAPABILITY_QUERY = `query PolicyInspectCapability($id: ID!) { capability(id: $id) { id name resourceKind } }`;
const ROLE_QUERY = `query PolicyInspectRole($id: ID!) { role(id: $id) { id name } }`;

type Row = Record<string, unknown>;

export function PolicyInspectDetails({ row }: { row: Row | null }) {
  const subjectKind = String(row?.subjectKind ?? "");
  const subjectId = String(row?.subjectId ?? "");
  const grantKind = String(row?.grantKind ?? "");
  const grantId = String(row?.grantId ?? "");
  const scopeKind = String(row?.scopeKind ?? "platform") as
    | "platform"
    | "tenant"
    | "object_kind"
    | "object_type"
    | "object";
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
  const grantName =
    capability?.name ??
    role?.name ??
    grantId.slice(0, 8) + "…";
  const grantLabel =
    capability
      ? `${capability.name}${capability.resourceKind ? ` (${capability.resourceKind})` : ""}`
      : grantName;

  const summary = summarizePolicy({
    effect,
    subjectKind: subjectKind as "entity" | "group",
    subjectName,
    grantKind: grantKind as "capability" | "role",
    grantName: grantLabel,
    scopeKind,
    scopeRef,
    conditions,
  });

  const fields: Array<{ label: string; value: string; mono?: boolean }> = [
    { label: "ID", value: String(row?.id ?? ""), mono: true },
    {
      label: "Effect",
      value: effect === "allow" ? "Allow" : "Deny",
    },
    {
      label: "Subject",
      value: entity
        ? `${entity.name} (${entity.kind})`
        : group
          ? `${group.name} — group`
          : `${subjectKind}: ${subjectId}`,
      mono: !entity && !group,
    },
    {
      label: "Grant",
      value: capability
        ? `${capability.name}${capability.resourceKind ? ` · ${capability.resourceKind}` : ""} — capability`
        : role
          ? `${role.name} — role`
          : `${grantKind}: ${grantId}`,
      mono: !capability && !role,
    },
    {
      label: "Scope",
      value: scopeSummary(scopeKind, scopeRef),
    },
  ];
  if (conditions.length > 0) {
    fields.push({
      label: "Conditions",
      value: conditions.map((c) => `${c.path} = ${c.value}`).join(", "),
    });
  }
  if (row?.createdAt) {
    fields.push({ label: "Created", value: String(row.createdAt) });
  }

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-4">
        <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Summary
        </div>
        <p className="mt-2 text-base leading-7">{summary}</p>
      </div>
      <div className="grid gap-2">
        {fields.map(({ label, value, mono }) => (
          <div key={label} className="flex gap-3 text-sm">
            <span className="w-24 shrink-0 font-medium text-muted-foreground">
              {label}
            </span>
            <span className={mono ? "font-mono text-xs" : ""}>{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

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
