"use client";

import { Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { StatusBadge } from "@/components/crud/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  excludeJoinedMembers,
  memberDisplayName,
  memberKindLabel,
  memberKindTitle,
  type ObjectMemberKind,
} from "@/lib/object-groups/membership";
import {
  useObjectGroupMemberCandidates,
  useObjectGroupMembers,
  useObjectGroupMembershipActions,
} from "@/lib/object-groups/use-object-group-membership";

const PAGE_SIZE = 10;

export function ObjectGroupMembersPanel({
  groupId,
  tenantId,
}: {
  groupId: string;
  tenantId?: string | null;
}) {
  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="text-sm font-medium">Members</div>
      <p className="text-xs text-muted-foreground">
        Entities and resources in this object group. Membership is many-to-many,
        so an object can belong to several object groups at once.
      </p>

      <Tabs defaultValue="entity">
        <TabsList className="mb-3">
          <TabsTrigger value="entity">Entities</TabsTrigger>
          <TabsTrigger value="resource">Resources</TabsTrigger>
        </TabsList>
        <TabsContent value="entity">
          <ObjectGroupMemberList
            groupId={groupId}
            kind="entity"
            tenantId={tenantId}
          />
        </TabsContent>
        <TabsContent value="resource">
          <ObjectGroupMemberList
            groupId={groupId}
            kind="resource"
            tenantId={tenantId}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ObjectGroupMemberList({
  groupId,
  kind,
  tenantId,
}: {
  groupId: string;
  kind: ObjectMemberKind;
  tenantId?: string | null;
}) {
  const [page, setPage] = React.useState(1);
  const [search, setSearch] = React.useState("");

  const membersQuery = useObjectGroupMembers({
    groupId,
    kind,
    page,
    pageSize: PAGE_SIZE,
  });
  const candidatesQuery = useObjectGroupMemberCandidates({
    kind,
    tenantId,
    search,
  });
  const { addToGroup, removeFromGroup } = useObjectGroupMembershipActions(kind);

  const members = membersQuery.data?.items ?? [];
  const total = membersQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const candidates = candidatesQuery.data ?? [];
  const addable = excludeJoinedMembers(candidates, groupId);

  return (
    <div className="grid gap-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium">{memberKindTitle(kind)}</span>
        <Badge variant="outline">{memberKindLabel(kind, total)}</Badge>
      </div>

      {membersQuery.isError ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {membersQuery.error.message}
        </div>
      ) : membersQuery.isFetching && members.length === 0 ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : members.length === 0 ? (
        <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          No {kind === "entity" ? "entities" : "resources"} in this group yet.
        </div>
      ) : (
        <div className="grid gap-2">
          {members.map((member) => (
            <div
              className="flex items-center justify-between gap-2 rounded-lg border bg-background px-3 py-2"
              key={member.id}
            >
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="truncate text-sm font-medium">
                  {memberDisplayName(member)}
                </span>
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {member.kind}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {member.status ? <StatusBadge value={member.status} /> : null}
                <Button
                  className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                  disabled={removeFromGroup.isPending}
                  onClick={() =>
                    removeFromGroup.mutate({
                      memberId: member.id,
                      objectGroupId: groupId,
                      message: `${memberDisplayName(member)} removed from this group`,
                    })
                  }
                  size="sm"
                  variant="ghost"
                >
                  <Trash2 className="size-3.5" />
                  <span className="sr-only">Remove from group</span>
                </Button>
              </div>
            </div>
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
              disabled={page <= 1 || membersQuery.isFetching}
              onClick={() => setPage((current) => current - 1)}
              size="sm"
              variant="outline"
            >
              Previous
            </Button>
            <Button
              disabled={page >= totalPages || membersQuery.isFetching}
              onClick={() => setPage((current) => current + 1)}
              size="sm"
              variant="outline"
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}

      {tenantId ? (
        <div className="grid gap-3 rounded-lg border bg-muted/30 p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Plus className="size-4 text-muted-foreground" />
            Add {kind}
          </div>
          <Input
            className="h-8 text-sm"
            onChange={(event) => setSearch(event.target.value)}
            placeholder={`Search ${kind === "entity" ? "entities" : "resources"}…`}
            value={search}
          />
          {candidatesQuery.isError ? (
            <div className="text-sm text-destructive">
              {candidatesQuery.error.message}
            </div>
          ) : addable.length === 0 ? (
            <div className="text-xs text-muted-foreground">
              {candidates.length > 0
                ? `Every matching ${kind === "entity" ? "entity is" : "resource is"} already in this group.`
                : search
                  ? `No matching ${kind === "entity" ? "entities" : "resources"}.`
                  : `No ${kind === "entity" ? "entities" : "resources"} available.`}
            </div>
          ) : (
            <ScrollArea className="max-h-48">
              <div className="grid gap-1">
                {addable.map((candidate) => (
                  <div
                    className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-muted"
                    key={candidate.id}
                  >
                    <div className="flex min-w-0 flex-col gap-0">
                      <span className="truncate text-xs font-medium">
                        {memberDisplayName(candidate)}
                      </span>
                      <span className="truncate font-mono text-xs text-muted-foreground">
                        {candidate.kind}
                      </span>
                    </div>
                    <Button
                      className="h-7 shrink-0 text-xs"
                      disabled={addToGroup.isPending}
                      onClick={() =>
                        addToGroup.mutate({
                          memberId: candidate.id,
                          objectGroupId: groupId,
                          message: `${memberDisplayName(candidate)} added to this group`,
                        })
                      }
                      size="sm"
                      variant="outline"
                    >
                      Add
                    </Button>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </div>
      ) : null}
    </div>
  );
}
