"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Trash2, UserPlus } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { StatusBadge } from "@/components/crud/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { graphqlClient } from "@/lib/graphql/client";

const GROUP_MEMBERS_QUERY = `
  query GroupMembers($groupId: ID!) {
    groupMembers(groupId: $groupId) {
      id
      name
      kind
      status
    }
  }
`;

const ENTITIES_QUERY = `
  query GroupMemberEntityPicker($limit: Int = 100, $offset: Int = 0) {
    entities(limit: $limit, offset: $offset) {
      items { id name kind tenantId status }
    }
  }
`;

const ADD_MEMBER_MUTATION = `
  mutation AddGroupMember($groupId: ID!, $entityId: ID!) {
    addGroupMember(groupId: $groupId, entityId: $entityId)
  }
`;

const REMOVE_MEMBER_MUTATION = `
  mutation RemoveGroupMember($groupId: ID!, $entityId: ID!) {
    removeGroupMember(groupId: $groupId, entityId: $entityId)
  }
`;

type Member = { id: string; name: string; kind: string; status: string };
type EntityOption = {
  id: string;
  name: string;
  kind: string;
  tenantId: string | null;
  status: string;
};

export function GroupMembersPanel({ groupId }: { groupId: string }) {
  const [search, setSearch] = React.useState("");

  const membersQuery = useQuery({
    queryKey: ["group-members", groupId],
    queryFn: ({ signal }) =>
      graphqlClient<{ groupMembers: Member[] }>({
        query: GROUP_MEMBERS_QUERY,
        variables: { groupId },
        signal,
      }),
    staleTime: 30_000,
  });

  const entitiesQuery = useQuery({
    queryKey: ["entity-picker"],
    queryFn: ({ signal }) =>
      graphqlClient<{ entities: { items: EntityOption[] } }>({
        query: ENTITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const members = membersQuery.data?.groupMembers ?? [];
  const memberIds = new Set(members.map((m) => m.id));

  const allEntities = entitiesQuery.data?.entities.items ?? [];
  const filtered = allEntities.filter(
    (e) =>
      !memberIds.has(e.id) &&
      (search === "" ||
        e.name.toLowerCase().includes(search.toLowerCase()) ||
        e.id.toLowerCase().includes(search.toLowerCase())),
  );

  const addMember = useMutation({
    mutationFn: (entityId: string) =>
      graphqlClient({
        query: ADD_MEMBER_MUTATION,
        variables: { groupId, entityId },
      }),
    onSuccess: () => {
      toast.success("Member added");
      membersQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const removeMember = useMutation({
    mutationFn: (entityId: string) =>
      graphqlClient({
        query: REMOVE_MEMBER_MUTATION,
        variables: { groupId, entityId },
      }),
    onSuccess: () => {
      toast.success("Member removed");
      membersQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <div className="grid gap-4">
      <div className="text-sm font-medium">Members</div>

      {membersQuery.isError ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {membersQuery.error.message}
        </div>
      ) : members.length === 0 ? (
        <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          No members yet.
        </div>
      ) : (
        <div className="grid gap-2">
          {members.map((member) => (
            <div
              key={member.id}
              className="flex items-center justify-between gap-2 rounded-lg border bg-background px-3 py-2"
            >
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="truncate text-sm font-medium">
                  {member.name}
                </span>
                <span className="text-xs text-muted-foreground">
                  {member.kind}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <StatusBadge value={member.status} />
                <Button
                  disabled={removeMember.isPending}
                  onClick={() => removeMember.mutate(member.id)}
                  size="sm"
                  variant="ghost"
                  className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="size-3.5" />
                  <span className="sr-only">Remove</span>
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-3 rounded-lg border bg-muted/30 p-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          <UserPlus className="size-4 text-muted-foreground" />
          Add member
        </div>
        <Input
          placeholder="Search entities…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-8 text-sm"
        />
        {entitiesQuery.isError ? (
          <div className="text-sm text-destructive">
            {entitiesQuery.error.message}
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-xs text-muted-foreground">
            {search
              ? "No matching entities."
              : "All entities are already members."}
          </div>
        ) : (
          <ScrollArea className="max-h-48">
            <div className="grid gap-1">
              {filtered.slice(0, 20).map((entity) => (
                <div
                  key={entity.id}
                  className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-muted"
                >
                  <div className="flex min-w-0 flex-col gap-0">
                    <span className="truncate text-xs font-medium">
                      {entity.name}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {entity.kind}
                      {entity.tenantId ? ` · ${entity.tenantId}` : ""}
                    </span>
                  </div>
                  <Button
                    disabled={addMember.isPending}
                    onClick={() => addMember.mutate(entity.id)}
                    size="sm"
                    variant="outline"
                    className="h-7 shrink-0 text-xs"
                  >
                    Add
                  </Button>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
    </div>
  );
}
