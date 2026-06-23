"use client";

import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { graphqlClient } from "@/lib/graphql/client";

const ROLE_PERMISSION_BLOCKS_QUERY = `
  query RolePermissionBlocksPanel($roleId: ID!) {
    role(id: $roleId) {
      permissionBlocks {
        id
        tenantId
        scopeMode
        objectKind
        objectType
        objectId
        groupId
        effect
        actions { id name description }
      }
    }
  }
`;

type Action = {
  id: string;
  name: string;
  description?: string | null;
};

type PermissionBlock = {
  id: string;
  tenantId?: string | null;
  scopeMode: string;
  objectKind?: string | null;
  objectType?: string | null;
  objectId?: string | null;
  groupId?: string | null;
  effect: string;
  actions: Action[];
};

export function RolePermissionBlocksPanel({ roleId }: { roleId: string }) {
  const { data, isFetching, error } = useQuery({
    queryKey: ["role-permission-blocks-panel", roleId],
    queryFn: ({ signal }) =>
      graphqlClient<{
        role: { permissionBlocks: PermissionBlock[] };
      }>({
        query: ROLE_PERMISSION_BLOCKS_QUERY,
        variables: { roleId },
        signal,
      }),
    staleTime: 30_000,
  });

  const permissionBlocks = data?.role.permissionBlocks ?? [];

  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="text-sm font-medium">Permission blocks</div>
      {isFetching && permissionBlocks.length === 0 ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : error ? (
        <p className="text-sm text-destructive">{error.message}</p>
      ) : permissionBlocks.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No permission blocks are attached to this role.
        </p>
      ) : (
        <div className="grid gap-2">
          {permissionBlocks.map((block) => (
            <div className="grid gap-2 rounded-md border p-2" key={block.id}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={
                    block.effect === "deny" ? "destructive" : "secondary"
                  }
                >
                  {block.effect}
                </Badge>
                <span className="text-sm font-medium">{scopeLabel(block)}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {block.actions.length === 0 ? (
                  <span className="text-sm text-muted-foreground">
                    No actions
                  </span>
                ) : (
                  block.actions.map((action) => (
                    <Badge
                      key={action.id}
                      title={action.description ?? undefined}
                      variant="outline"
                    >
                      {action.name}
                    </Badge>
                  ))
                )}
              </div>
              <div className="break-all font-mono text-xs text-muted-foreground">
                {block.id}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function scopeLabel(block: PermissionBlock) {
  switch (block.scopeMode) {
    case "platform":
      return "Platform";
    case "tenant":
      return block.tenantId ? `Tenant ${block.tenantId}` : "Tenant";
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
