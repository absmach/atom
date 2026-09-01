"use client";

import { useQuery } from "@tanstack/react-query";
import { UserRound, UsersRound } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  type AccessObjectKind,
  DIRECT_POLICIES_FOR_OBJECT_QUERY,
  type DirectPolicyPage,
  type DirectPolicyRow,
  directPolicyReachLabel,
  directPolicyScopeGroupIds,
  directPolicySubjectIds,
  isGroupSubject,
} from "@/lib/access/object-access";
import { graphqlClient } from "@/lib/graphql/client";
import { useNameMap } from "@/lib/reconcile/use-name-map";
import { Action } from "@/lib/utils";

const PAGE_SIZE = 10;

/**
 * Read-only reverse policy lookup. Grants are created from the Policies page;
 * this only answers who the object is currently shared with.
 */
export function ObjectAccessPanel({
  objectId,
  objectKind,
}: {
  objectId: string;
  objectKind: AccessObjectKind;
}) {
  const [page, setPage] = React.useState(1);

  const { data, error, isFetching } = useQuery({
    enabled: Boolean(objectId),
    queryKey: ["object-direct-policies", objectKind, objectId, page],
    queryFn: ({ signal }) =>
      graphqlClient<{ directPolicies: DirectPolicyPage }>({
        query: DIRECT_POLICIES_FOR_OBJECT_QUERY,
        variables: {
          objectId,
          objectKind,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      }),
    staleTime: 30_000,
    placeholderData: (previous) => previous,
  });

  const items = data?.directPolicies.items ?? [];
  const total = data?.directPolicies.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const { entityIds, groupIds } = directPolicySubjectIds(items);
  const names = useNameMap({
    entityIds,
    groupIds: [...groupIds, ...directPolicyScopeGroupIds(items)],
  });

  return (
    <div className="grid gap-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-medium">Shared with</div>
        <Badge variant="outline">{total} direct policies</Badge>
      </div>
      <p className="text-xs text-muted-foreground">
        Subjects granted access by a policy that names this {objectKind} —
        directly, or through an object group it belongs to. Access inherited
        from roles, and broad platform, tenant, or kind-wide grants, are not
        listed here.
      </p>

      {error ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error.message}
        </div>
      ) : isFetching && items.length === 0 ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : items.length === 0 ? (
        <div className="rounded-lg border bg-muted/30 p-4 text-center text-sm text-muted-foreground">
          This {objectKind} is not shared with anyone directly.
        </div>
      ) : (
        <div className="grid gap-2">
          {items.map((policy) => (
            <AccessRow key={policy.id} names={names} policy={policy} />
          ))}
        </div>
      )}

      {totalPages > 1 ? (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            Page {page} of {totalPages} · {total} total
          </span>
          <div className="flex gap-2">
            <Button
              disabled={page <= 1 || isFetching}
              onClick={() => setPage((current) => current - 1)}
              size="sm"
              variant="outline"
            >
              Previous
            </Button>
            <Button
              disabled={page >= totalPages || isFetching}
              onClick={() => setPage((current) => current + 1)}
              size="sm"
              variant="outline"
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function AccessRow({
  names,
  policy,
}: {
  names: Map<string, string>;
  policy: DirectPolicyRow;
}) {
  const isGroup = isGroupSubject(policy.subjectKind);
  const Icon = isGroup ? UsersRound : UserRound;
  const subjectName = names.get(policy.subjectId) ?? policy.subjectId;
  const block = policy.permissionBlock;
  const scopeGroupName = block.groupId ? names.get(block.groupId) : undefined;

  return (
    <div className="grid gap-2 rounded-md border p-2">
      <div className="flex min-w-0 items-start gap-2">
        <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted text-muted-foreground">
          <Icon className="size-4" />
        </span>
        <div className="grid min-w-0 flex-1 gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 truncate text-sm font-medium">
              {subjectName}
            </span>
            <Badge variant="secondary">
              {isGroup ? "Principal group" : "Entity"}
            </Badge>
            <Badge
              variant={block.effect === "deny" ? "destructive" : "outline"}
            >
              {block.effect}
            </Badge>
          </div>
          <div className="flex flex-wrap gap-1">
            {block.actions.length === 0 ? (
              <span className="text-xs text-muted-foreground">No actions</span>
            ) : (
              block.actions.map((action) => (
                <Badge key={action.name} variant="outline">
                  {action.name}
                </Badge>
              ))
            )}
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span>{directPolicyReachLabel(block, scopeGroupName)}</span>
            <span>
              Granted{" "}
              <DisplayTimeCell
                action={Action.Created}
                time={policy.createdAt}
              />
            </span>
          </div>
        </div>
      </div>
      <div className="break-all font-mono text-xs text-muted-foreground">
        {policy.subjectId}
      </div>
    </div>
  );
}
