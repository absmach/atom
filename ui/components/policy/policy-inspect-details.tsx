"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const ENTITY_QUERY = `query DirectPolicyInspectEntity($id: ID!) { entity(id: $id) { id name kind } }`;
const GROUP_QUERY = `query DirectPolicyInspectGroup($id: ID!) { group(id: $id) { id name groupType } }`;
const PERMISSION_BLOCK_QUERY = `
  query DirectPolicyInspectPermissionBlock($id: ID!) {
    permissionBlock(id: $id) {
      id tenantId scopeMode objectKind objectType objectId groupId effect actions { id name }
    }
  }
`;

type Row = Record<string, unknown>;

type PermissionBlock = {
  id: string;
  tenantId?: string | null;
  scopeMode: string;
  objectKind?: string | null;
  objectType?: string | null;
  objectId?: string | null;
  groupId?: string | null;
  effect: string;
  actions: { id: string; name: string }[];
};

export function PolicyInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);

  const id = row ? String(row.id ?? "") : "";
  const tenantId = row?.tenantId ? String(row.tenantId) : "";
  const subjectKind = row ? String(row.subjectKind ?? "") : "";
  const subjectId = row ? String(row.subjectId ?? "") : "";
  const permissionBlockId = row ? String(row.permissionBlockId ?? "") : "";

  const entityQ = useQuery({
    enabled: Boolean(row) && subjectKind === "entity" && Boolean(subjectId),
    queryKey: ["direct-policy-inspect-entity", subjectId],
    queryFn: ({ signal }) =>
      graphqlClient<{ entity: { id: string; name: string; kind: string } }>({
        query: ENTITY_QUERY,
        variables: { id: subjectId },
        signal,
      }),
    staleTime: 60_000,
  });

  const groupQ = useQuery({
    enabled: Boolean(row) && subjectKind === "group" && Boolean(subjectId),
    queryKey: ["direct-policy-inspect-group", subjectId],
    queryFn: ({ signal }) =>
      graphqlClient<{
        group: { id: string; name: string; groupType?: string | null };
      }>({
        query: GROUP_QUERY,
        variables: { id: subjectId },
        signal,
      }),
    staleTime: 60_000,
  });

  const blockQ = useQuery({
    enabled: Boolean(row) && Boolean(permissionBlockId),
    queryKey: ["direct-policy-inspect-permission-block", permissionBlockId],
    queryFn: ({ signal }) =>
      graphqlClient<{ permissionBlock: PermissionBlock }>({
        query: PERMISSION_BLOCK_QUERY,
        variables: { id: permissionBlockId },
        signal,
      }),
    staleTime: 60_000,
  });

  const block = blockQ.data?.permissionBlock;
  const entity = entityQ.data?.entity;
  const group = groupQ.data?.group;

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-4">
        <div className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Summary
        </div>
        <p className="text-sm">
          Directly grants{" "}
          <span className="font-medium">
            {block ? scopeLabel(block) : permissionBlockId}
          </span>{" "}
          to{" "}
          <span className="font-medium">
            {entity
              ? `${entity.name} (${entity.kind})`
              : group
                ? `${group.name} (${group.groupType ?? "group"})`
                : subjectId}
          </span>
          .
        </p>
      </div>

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

      <Field label="Tenant">
        <span className="break-all font-mono text-xs">
          {tenantId || "platform"}
        </span>
      </Field>

      <Field label="Subject">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="secondary">{subjectKind}</Badge>
          <span className="text-sm">
            {entity
              ? `${entity.name} (${entity.kind})`
              : group
                ? group.name
                : subjectId}
          </span>
        </div>
      </Field>

      <Field label="Permission block">
        {block ? (
          <div className="grid gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={block.effect === "deny" ? "destructive" : "secondary"}
              >
                {block.effect}
              </Badge>
              <span className="text-sm">{scopeLabel(block)}</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {block.actions.map((action) => (
                <Badge key={action.id} variant="outline">
                  {action.name}
                </Badge>
              ))}
            </div>
            <span className="break-all font-mono text-xs text-muted-foreground">
              {permissionBlockId}
            </span>
          </div>
        ) : (
          <span className="break-all font-mono text-xs">
            {permissionBlockId}
          </span>
        )}
      </Field>

      {row.createdAt ? (
        <Field label="Created">
          <DisplayTimeCell
            action={Action.Created}
            time={String(row.createdAt)}
          />
        </Field>
      ) : null}
    </div>
  );
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

function scopeLabel(block: PermissionBlock) {
  switch (block.scopeMode) {
    case "platform":
      return "Platform";
    case "tenant":
      return "Tenant";
    case "object_kind":
      return `All ${block.objectKind ?? "objects"}`;
    case "object_type":
      return `All ${block.objectKind ?? "objects"}:${block.objectType ?? "*"}`;
    case "object":
      return `${block.objectKind ?? "object"} ${block.objectId ?? ""}`.trim();
    case "group":
      return `Object group ${block.groupId ?? ""}`.trim();
    case "group_direct_objects":
      return `Direct ${block.objectKind ?? "objects"} in group ${block.groupId ?? ""}`.trim();
    case "group_descendant_objects":
      return `Descendant ${block.objectKind ?? "objects"} in group ${block.groupId ?? ""}`.trim();
    case "group_child_groups":
      return `Direct child groups of ${block.groupId ?? ""}`.trim();
    case "group_descendant_groups":
      return `Descendant groups of ${block.groupId ?? ""}`.trim();
    default:
      return block.scopeMode;
  }
}
