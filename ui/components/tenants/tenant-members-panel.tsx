"use client";

import { useQuery } from "@tanstack/react-query";
import { Search, UsersRound } from "lucide-react";
import * as React from "react";
import { StatusBadge } from "@/components/crud/status-badge";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { graphqlClient } from "@/lib/graphql/client";

const TENANT_MEMBERS_QUERY = `
  query TenantMembersPanel(
    $tenantId: ID!
    $q: String
    $limit: Int = 100
    $offset: Int = 0
  ) {
    tenantMembers(
      tenantId: $tenantId
      q: $q
      limit: $limit
      offset: $offset
    ) {
      total
      items {
        id
        name
        kind
        tenantId
        status
      }
    }
  }
`;

type TenantMember = {
  id: string;
  name: string;
  kind: string;
  tenantId?: string | null;
  status: string;
};

type TenantMembersData = {
  tenantMembers: {
    total: number;
    items: TenantMember[];
  };
};

export function TenantMembersPanel({ tenantId }: { tenantId: string }) {
  const [search, setSearch] = React.useState("");
  const queryValue = search.trim();

  const membersQuery = useQuery({
    queryKey: ["tenant-members-panel", tenantId, queryValue],
    queryFn: ({ signal }) =>
      graphqlClient<TenantMembersData>({
        query: TENANT_MEMBERS_QUERY,
        variables: {
          tenantId,
          q: queryValue || null,
          limit: 100,
          offset: 0,
        },
        signal,
      }),
    staleTime: 30_000,
  });

  const members = membersQuery.data?.tenantMembers.items ?? [];
  const total = membersQuery.data?.tenantMembers.total ?? 0;

  return (
    <div className="grid gap-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-2">
          <UsersRound className="size-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 text-sm font-medium">Tenant members</div>
          <Badge variant="outline">{memberCountLabel(total)}</Badge>
        </div>
        <div className="relative sm:w-72">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            aria-label="Search tenant members"
            className="h-8 pl-8 text-sm"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search members"
            value={search}
          />
        </div>
      </div>

      {membersQuery.isFetching && !membersQuery.data ? (
        <p className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          Loading members...
        </p>
      ) : membersQuery.isError ? (
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {membersQuery.error.message}
        </p>
      ) : members.length === 0 ? (
        <p className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          {queryValue ? "No matching members." : "No active members."}
        </p>
      ) : (
        <div className="grid gap-2">
          {members.map((member) => (
            <MemberRow key={member.id} member={member} />
          ))}
        </div>
      )}

      {total > members.length ? (
        <p className="text-xs text-muted-foreground">
          Showing first {members.length} of {total} members.
        </p>
      ) : null}
    </div>
  );
}

function MemberRow({ member }: { member: TenantMember }) {
  return (
    <div className="grid gap-2 rounded-lg border bg-background p-3">
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 truncate text-sm font-medium">
              {member.name}
            </span>
            <Badge variant="secondary">{member.kind}</Badge>
            <StatusBadge value={member.status} />
          </div>
          <div className="flex min-w-0 flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span className="break-all font-mono">{member.id}</span>
            {member.tenantId ? (
              <span className="break-all">Home tenant {member.tenantId}</span>
            ) : (
              <span>Global entity</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function memberCountLabel(total: number) {
  return `${total} active`;
}
