"use client";

import { Plus, X } from "lucide-react";
import * as React from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ObjectMemberKind } from "@/lib/object-groups/membership";
import {
  useObjectGroupIds,
  useObjectGroupMembershipActions,
  useObjectGroupOptions,
} from "@/lib/object-groups/use-object-group-membership";
import { useNameMap } from "@/lib/reconcile/use-name-map";

/**
 * Object-group membership seen from the entity/resource side. The same
 * mutations back the group-side panel, so both views stay in step.
 */
export function ObjectGroupMembershipField({
  initialObjectGroupIds,
  kind,
  memberId,
  tenantId,
}: {
  initialObjectGroupIds: string[];
  kind: ObjectMemberKind;
  memberId: string;
  tenantId?: string | null;
}) {
  const [search, setSearch] = React.useState("");

  const { data: objectGroupIds = [] } = useObjectGroupIds({
    kind,
    memberId,
    initialObjectGroupIds,
  });
  const optionsQuery = useObjectGroupOptions({ tenantId, search });
  const { addToGroup, removeFromGroup, clearGroups } =
    useObjectGroupMembershipActions(kind);

  const names = useNameMap({ groupIds: objectGroupIds });
  const options = optionsQuery.data ?? [];
  const isPlatformScoped = !tenantId;

  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs font-medium uppercase text-muted-foreground">
          Object groups
        </div>
        {objectGroupIds.length > 0 ? (
          <Badge variant="outline">{objectGroupIds.length} joined</Badge>
        ) : null}
      </div>

      {objectGroupIds.length === 0 ? (
        <span className="text-sm text-muted-foreground">
          Not a member of any object group.
        </span>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {objectGroupIds.map((groupId) => {
            const name = names.get(groupId) ?? groupId;
            return (
              <span
                className="flex items-center gap-1 rounded-md bg-muted px-2 py-1 text-xs"
                key={groupId}
              >
                <span className="max-w-40 truncate">{name}</span>
                <Button
                  className="size-4 p-0 text-muted-foreground hover:text-destructive"
                  disabled={removeFromGroup.isPending}
                  onClick={() =>
                    removeFromGroup.mutate({
                      memberId,
                      objectGroupId: groupId,
                      message: `Removed from ${name}`,
                    })
                  }
                  size="icon"
                  variant="ghost"
                >
                  <X className="size-3" />
                  <span className="sr-only">Remove from {name}</span>
                </Button>
              </span>
            );
          })}
        </div>
      )}

      {isPlatformScoped ? (
        <p className="text-xs text-muted-foreground">
          Platform-scoped {kind === "entity" ? "entities" : "resources"} cannot
          join an object group. Assign a tenant first.
        </p>
      ) : (
        <div className="grid gap-2 rounded-lg border bg-muted/30 p-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Plus className="size-4 text-muted-foreground" />
            Add to object group
          </div>
          <Input
            className="h-8 text-sm"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search object groups…"
            value={search}
          />
          {optionsQuery.isError ? (
            <div className="text-sm text-destructive">
              {optionsQuery.error.message}
            </div>
          ) : options.length === 0 ? (
            <div className="text-xs text-muted-foreground">
              {search
                ? "No matching object groups."
                : "No object groups in this tenant."}
            </div>
          ) : (
            <ScrollArea className="max-h-40">
              <div className="grid gap-1">
                {options.map((option) => (
                  <div
                    className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-muted"
                    key={option.id}
                  >
                    <span className="truncate text-xs font-medium">
                      {option.name}
                    </span>
                    <Button
                      className="h-7 shrink-0 text-xs"
                      disabled={addToGroup.isPending}
                      onClick={() =>
                        addToGroup.mutate({
                          memberId,
                          objectGroupId: option.id,
                          message: `Added to ${option.name}`,
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
      )}

      {objectGroupIds.length > 0 ? (
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button
              className="justify-self-start"
              disabled={clearGroups.isPending}
              size="sm"
              variant="outline"
            >
              Remove from all object groups
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                Remove from all object groups?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This drops every one of the {objectGroupIds.length} object group
                memberships at once. Access granted through those groups stops
                applying to this {kind}.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => clearGroups.mutate({ memberId })}
              >
                Remove from all
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      ) : null}
    </div>
  );
}
