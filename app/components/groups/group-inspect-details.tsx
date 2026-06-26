"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const TENANT_QUERY = `
  query GroupInspectTenant($id: ID!) {
    tenant(id: $id) { id name }
  }
`;

type Row = Record<string, unknown>;

export function GroupInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);

  const id = row?.id ? String(row.id) : "";
  const tenantId = row?.tenantId ? String(row.tenantId) : "";
  const parentId = row?.parentId ? String(row.parentId) : "";
  const groupType = row?.groupType ? String(row.groupType) : "";

  const tenantQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ["group-inspect-tenant", tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenant: { id: string; name: string } }>({
        query: TENANT_QUERY,
        variables: { id: tenantId },
        signal,
      }),
    staleTime: 60_000,
  });
  const hierarchyQuery = useQuery({
    enabled: Boolean(id),
    queryKey: ["group-inspect-hierarchy", id, parentId],
    queryFn: ({ signal }) =>
      graphqlClient<{
        childGroups: { items: { id: string; name: string }[] };
        parent?: { id: string; name: string } | null;
      }>({
        query: parentId
          ? `query GroupInspectHierarchy($id: ID!, $parentId: ID!) {
              childGroups(parentId: $id, limit: 50, offset: 0) { items { id name } }
              parent: group(id: $parentId) { id name }
            }`
          : `query GroupInspectHierarchy($id: ID!) {
              childGroups(parentId: $id, limit: 50, offset: 0) { items { id name } }
            }`,
        variables: parentId ? { id, parentId } : { id },
        signal,
      }),
    staleTime: 30_000,
  });

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  const tenantName = tenantQuery.data?.tenant.name ?? tenantId;

  return (
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

      {row.name ? (
        <Field label="Name">
          <span className="text-sm">{String(row.name)}</span>
        </Field>
      ) : null}

      {tenantId ? (
        <Field label="Tenant">
          <span className="text-sm">{tenantName}</span>
        </Field>
      ) : null}

      {row.description ? (
        <Field label="Description">
          <span className="text-sm">{String(row.description)}</span>
        </Field>
      ) : null}

      <Field label="Group type">
        <span className="text-sm">{groupTypeLabel(groupType)}</span>
      </Field>

      <Field label="Parent group">
        <span className="text-sm">
          {parentId
            ? (hierarchyQuery.data?.parent?.name ?? parentId)
            : "No parent"}
        </span>
      </Field>

      <Field label={childGroupsLabel(groupType)}>
        {hierarchyQuery.data?.childGroups.items.length ? (
          <div className="flex flex-wrap gap-1">
            {hierarchyQuery.data.childGroups.items.map((child) => (
              <span
                key={child.id}
                className="rounded-md bg-muted px-2 py-1 text-xs"
              >
                {child.name}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-sm text-muted-foreground">No child groups</span>
        )}
        <p className="mt-2 text-xs text-muted-foreground">
          {groupType === "principal"
            ? "Principal Group nesting extends inherited role assignments to member entities and child Principal Groups."
            : "Object Group nesting only defines where a role applies. Access is still granted through role assignments to entities or Principal Groups."}
        </p>
      </Field>

      <div className="grid gap-3 sm:grid-cols-2">
        {row.createdAt ? (
          <Field label="Created">
            <DisplayTimeCell
              action={Action.Created}
              time={String(row.createdAt)}
            />
          </Field>
        ) : null}
        {row.updatedAt ? (
          <Field label="Updated">
            <DisplayTimeCell
              action={Action.Updated}
              time={String(row.updatedAt)}
            />
          </Field>
        ) : null}
      </div>
    </div>
  );
}

function groupTypeLabel(groupType: string) {
  if (groupType === "principal") return "Principal group";
  if (groupType === "object") return "Object group";
  return "Group";
}

function childGroupsLabel(groupType: string) {
  if (groupType === "principal") return "Child Principal Groups";
  if (groupType === "object") return "Child Object Groups";
  return "Child Groups";
}

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
