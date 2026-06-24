"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import {
  DeleteActionButtons,
  EntityActionButtons,
  ProfileActionButtons,
  TenantActionButtons,
} from "@/components/crud/table/action-buttons";
import { renderCell } from "@/components/crud/table/cell-rendering";
import {
  ENTITY_STATUS_MUTATIONS,
  PROFILE_STATUS_MUTATION,
  TENANT_STATUS_MUTATIONS,
} from "@/components/crud/table/constants";
import { CrudCreateSheet } from "@/components/crud/table/create-sheet";
import {
  CrudEditSheets,
  type EditingRows,
  type EditingSetters,
} from "@/components/crud/table/edit-sheets";
import { CrudInspectSheet } from "@/components/crud/table/inspect-sheet";
import type { CrudTableProps, Row } from "@/components/crud/table/types";
import {
  defer,
  isDeletedRow,
  singularize,
  tenantActionPastTense,
} from "@/components/crud/table/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/ui/data-table";
import { requireResource } from "@/lib/crud/resources";
import {
  PERMANENT_DELETE_WARNING,
  SOFT_DELETE_RETENTION_NOTE,
} from "@/lib/crud/retention";
import { graphqlClient } from "@/lib/graphql/client";
import { extractIds, useNameMap } from "@/lib/reconcile/use-name-map";

export type { CrudTableProps };

export function CrudTable({
  filters,
  resourceKey,
  rows,
  total,
  page,
  limit,
  source,
  showDeletedColumns = false,
}: CrudTableProps) {
  const resource = requireResource(resourceKey);
  const router = useRouter();
  const queryClient = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [inspected, setInspected] = React.useState<Row | null>(null);
  const [editingTenant, setEditingTenant] = React.useState<Row | null>(null);
  const [editingEntity, setEditingEntity] = React.useState<Row | null>(null);
  const [editingProfile, setEditingProfile] = React.useState<Row | null>(null);
  const [editingGroup, setEditingGroup] = React.useState<Row | null>(null);
  const [editingResource, setEditingResource] = React.useState<Row | null>(
    null,
  );
  const [editingRole, setEditingRole] = React.useState<Row | null>(null);
  const [editingPolicy, setEditingPolicy] = React.useState<Row | null>(null);
  const [editingActionApplicability, setEditingActionApplicability] =
    React.useState<Row | null>(null);

  const nameMap = useNameMap(extractIds(resourceKey, rows));

  const refresh = React.useCallback(() => {
    setOpen(false);
    router.refresh();
  }, [router]);

  const create = useMutation({
    mutationFn: async (input: Record<string, unknown>) => {
      if (!resource.createMutation) {
        throw new Error(
          resource.missing.create ??
            "Create is not available for this resource.",
        );
      }
      return graphqlClient({
        query: resource.createMutation,
        variables: { input },
      });
    },
    onSuccess: () => {
      toast.success(`${resource.title} item created`);
      setOpen(false);
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const destroy = useMutation({
    mutationFn: async (row: Row) => {
      if (!resource.deleteMutation) {
        throw new Error(
          resource.missing.delete ??
            "Delete is not available for this resource.",
        );
      }
      const idField = resource.deleteIdField ?? "id";
      if (resource.key === "action-applicability") {
        return graphqlClient({
          query: resource.deleteMutation,
          variables: {
            input: {
              actionId: row.actionId,
              objectKind: row.objectKind,
              objectType: row.objectType ?? null,
            },
          },
        });
      }
      return graphqlClient({
        query: resource.deleteMutation,
        variables: { id: row[idField] },
      });
    },
    onSuccess: () => {
      toast.success(`${singularize(resource.title)} deleted`);
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const restore = useMutation({
    mutationFn: async (row: Row) => {
      if (!resource.restoreMutation) {
        throw new Error("Restore is not available for this resource.");
      }
      return graphqlClient({
        query: resource.restoreMutation,
        variables: { id: row.id },
      });
    },
    onSuccess: () => {
      toast.success(`${singularize(resource.title)} restored`);
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const purge = useMutation({
    mutationFn: async (row: Row) => {
      if (!resource.purgeMutation) {
        throw new Error("Permanent delete is not available for this resource.");
      }
      return graphqlClient({
        query: resource.purgeMutation,
        variables: { id: row.id },
      });
    },
    onSuccess: () => {
      toast.success(`${singularize(resource.title)} permanently deleted`);
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const tenantStatus = useMutation({
    mutationFn: async ({
      action,
      row,
    }: {
      action: keyof typeof TENANT_STATUS_MUTATIONS;
      row: Row;
    }) =>
      graphqlClient({
        query: TENANT_STATUS_MUTATIONS[action],
        variables: { id: row.id },
      }),
    onSuccess: (_data, variables) => {
      toast.success(`Tenant ${tenantActionPastTense(variables.action)}`);
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const entityStatus = useMutation({
    mutationFn: async ({
      action,
      row,
    }: {
      action: keyof typeof ENTITY_STATUS_MUTATIONS;
      row: Row;
    }) =>
      graphqlClient({
        query: ENTITY_STATUS_MUTATIONS[action],
        variables: { id: row.id },
      }),
    onSuccess: (_data, variables) => {
      toast.success(
        `Entity ${variables.action === "enable" ? "enabled" : "disabled"}`,
      );
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  const profileStatus = useMutation({
    mutationFn: async ({
      status,
      row,
    }: {
      status: "active" | "disabled";
      row: Row;
    }) =>
      graphqlClient({
        query: PROFILE_STATUS_MUTATION,
        variables: { id: row.id, input: { status } },
      }),
    onSuccess: (_data, variables) => {
      toast.success(
        `Profile ${variables.status === "active" ? "enabled" : "disabled"}`,
      );
      queryClient.invalidateQueries({
        queryKey: ["profile-inspect", String(variables.row.id)],
      });
      router.refresh();
    },
    onError: (error) => toast.error(error.message),
  });

  function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const rawInput = Object.fromEntries(
      Array.from(form.entries()).filter(([, v]) => String(v).trim().length > 0),
    );
    const input: Record<string, unknown> = { ...rawInput };
    if (resource.formAttributes) {
      if (typeof input.attributes === "string") {
        try {
          input.attributes = JSON.parse(input.attributes);
        } catch {
          toast.error("Attributes must be valid JSON.");
          return;
        }
      }
      if (input.attributes === undefined) {
        input.attributes = {};
      }
      input.attributes = {
        ...(input.attributes as Record<string, unknown>),
      };
    }
    create.mutate(input);
  }

  const visibleColumns = showDeletedColumns
    ? resource.columns
    : resource.columns.filter(
        (col) => col.key !== "deletedAt" && col.key !== "deletedBy",
      );

  const columns: ColumnDef<Row>[] = [
    ...visibleColumns.map((col) => ({
      accessorKey: col.key,
      header: col.label,
      cell: ({ getValue }: { getValue: () => unknown }) =>
        renderCell(getValue(), col.key, nameMap),
    })),
    {
      id: "_row_actions",
      // Pin the actions to the right edge so they stay visible while the rest of
      // the (often wide) row scrolls horizontally underneath.
      meta: {
        className: "sticky right-0 z-10 bg-card",
      },
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }: { row: { original: Row } }) => (
        <TableRowActions
          destroyPending={destroy.isPending}
          entityStatusPending={entityStatus.isPending}
          onDelete={(label) => {
            if (window.confirm(label)) destroy.mutate(row.original);
          }}
          onRestore={() => restore.mutate(row.original)}
          restorePending={restore.isPending}
          canRestore={Boolean(resource.restoreMutation)}
          onPurge={(label) => {
            if (window.confirm(label)) purge.mutate(row.original);
          }}
          purgePending={purge.isPending}
          canPurge={Boolean(resource.purgeMutation)}
          onEdit={editingSetters}
          onInspect={() => defer(() => setInspected(row.original))}
          onEntityStatusChange={(action) =>
            entityStatus.mutate({ action, row: row.original })
          }
          onProfileStatusChange={(status) =>
            profileStatus.mutate({ status, row: row.original })
          }
          onTenantStatusChange={(action) =>
            tenantStatus.mutate({ action, row: row.original })
          }
          profileStatusPending={profileStatus.isPending}
          missingDelete={Boolean(resource.missing.delete)}
          missingUpdate={Boolean(resource.missing.update)}
          resourceKey={resource.key}
          row={row.original}
          tenantStatusPending={tenantStatus.isPending}
        />
      ),
    },
  ];

  const editingRows: EditingRows = {
    tenant: editingTenant,
    entity: editingEntity,
    profile: editingProfile,
    group: editingGroup,
    resource: editingResource,
    role: editingRole,
    actionApplicability: editingActionApplicability,
    policy: editingPolicy,
  };

  const editingSetters: EditingSetters = {
    setTenant: setEditingTenant,
    setEntity: setEditingEntity,
    setProfile: setEditingProfile,
    setGroup: setEditingGroup,
    setResource: setEditingResource,
    setRole: setEditingRole,
    setActionApplicability: setEditingActionApplicability,
    setPolicy: setEditingPolicy,
  };

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        filters={filters ?? resource.filters}
        limit={limit}
        noResultsMessage={`No ${resource.title.toLowerCase()} found.`}
        page={page}
        paramKey={resourceKey}
        searchPlaceholder={`Filter ${resource.title.toLowerCase()}...`}
        statusFilter={{
          enabled: resource.columns.some((column) => column.key === "status"),
          options: resource.statusOptions,
        }}
        toolbar={
          <div className="flex items-center gap-2">
            {source === "scaffold" ? (
              <Badge variant="outline" className="text-muted-foreground">
                Sample data
              </Badge>
            ) : null}
            <Button
              aria-expanded={open}
              aria-haspopup="dialog"
              disabled={Boolean(resource.missing.create)}
              onClick={() => defer(() => setOpen(true))}
            >
              <Plus data-icon="inline-start" />
              Create
            </Button>
          </div>
        }
        total={total}
      />

      <CrudCreateSheet
        createIsPending={create.isPending}
        onOpenChange={setOpen}
        onRefresh={refresh}
        onSubmitFallback={submit}
        open={open}
        resource={resource}
      />
      <CrudEditSheets
        editing={editingRows}
        onRefresh={() => router.refresh()}
        setters={editingSetters}
      />
      <CrudInspectSheet
        inspected={inspected}
        onClose={() => setInspected(null)}
        resource={resource}
      />
    </>
  );
}

function TableRowActions({
  destroyPending,
  entityStatusPending,
  onDelete,
  onRestore,
  restorePending,
  canRestore,
  onPurge,
  purgePending,
  canPurge,
  onEdit,
  onEntityStatusChange,
  onInspect,
  onProfileStatusChange,
  onTenantStatusChange,
  missingDelete,
  missingUpdate,
  profileStatusPending,
  resourceKey,
  row,
  tenantStatusPending,
}: {
  destroyPending: boolean;
  entityStatusPending: boolean;
  onDelete: (label: string) => void;
  onRestore: () => void;
  restorePending: boolean;
  canRestore: boolean;
  onPurge: (label: string) => void;
  purgePending: boolean;
  canPurge: boolean;
  onEdit: EditingSetters;
  onEntityStatusChange: (action: keyof typeof ENTITY_STATUS_MUTATIONS) => void;
  onInspect: () => void;
  onProfileStatusChange: (status: "active" | "disabled") => void;
  onTenantStatusChange: (action: keyof typeof TENANT_STATUS_MUTATIONS) => void;
  missingDelete: boolean;
  missingUpdate: boolean;
  profileStatusPending: boolean;
  resourceKey: string;
  row: Row;
  tenantStatusPending: boolean;
}) {
  if (isDeletedRow(row)) {
    return (
      <div className="flex justify-end gap-2">
        <Button onClick={onInspect} size="sm" variant="outline">
          Inspect
        </Button>
        {canRestore ? (
          <Button
            disabled={restorePending}
            onClick={onRestore}
            size="sm"
            variant="outline"
            className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
          >
            Restore
          </Button>
        ) : null}
        {canPurge ? (
          <Button
            disabled={purgePending}
            onClick={() =>
              onPurge(
                `Permanently delete "${String(row.name ?? row.id)}"? ${PERMANENT_DELETE_WARNING}`,
              )
            }
            size="sm"
            variant="destructive"
          >
            Delete permanently
          </Button>
        ) : null}
      </div>
    );
  }

  return (
    <div className="flex justify-end gap-2">
      <Button onClick={onInspect} size="sm" variant="outline">
        Inspect
      </Button>
      {resourceKey === "tenants" ? (
        <TenantActionButtons
          isDestroyPending={destroyPending}
          isPending={tenantStatusPending}
          onDelete={() =>
            onDelete(
              `Delete tenant "${String(row.name ?? row.id)}"? Revokes child sessions. ${SOFT_DELETE_RETENTION_NOTE}`,
            )
          }
          onEdit={() => onEdit.setTenant(row)}
          onStatusChange={onTenantStatusChange}
          row={row}
        />
      ) : resourceKey === "entities" ? (
        <EntityActionButtons
          isDestroyPending={destroyPending}
          isPending={entityStatusPending}
          onDelete={() =>
            onDelete(
              `Delete entity "${String(row.name ?? row.id)}"? Revokes its credentials and sessions. ${SOFT_DELETE_RETENTION_NOTE}`,
            )
          }
          onEdit={() => defer(() => onEdit.setEntity(row))}
          onStatusChange={onEntityStatusChange}
          row={row}
        />
      ) : resourceKey === "profiles" ? (
        <ProfileActionButtons
          isPending={profileStatusPending}
          onEdit={() => defer(() => onEdit.setProfile(row))}
          onStatusChange={onProfileStatusChange}
          row={row}
        />
      ) : resourceKey === "groups" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setGroup(row))}
          onDelete={() =>
            onDelete(
              `Delete group "${String(row.name ?? row.id)}"? ${SOFT_DELETE_RETENTION_NOTE}`,
            )
          }
        />
      ) : resourceKey === "resources" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setResource(row))}
          onDelete={() =>
            onDelete(
              `Delete resource "${String(row.name ?? row.id)}"? ${SOFT_DELETE_RETENTION_NOTE}`,
            )
          }
        />
      ) : resourceKey === "roles" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setRole(row))}
          onDelete={() =>
            onDelete(
              `Delete role "${String(row.name ?? row.id)}"? ${SOFT_DELETE_RETENTION_NOTE}`,
            )
          }
        />
      ) : resourceKey === "action-applicability" ? (
        <>
          {!missingUpdate && (
            <Button
              onClick={() => defer(() => onEdit.setActionApplicability(row))}
              size="sm"
              variant="outline"
            >
              Edit
            </Button>
          )}
          <Button
            disabled={missingDelete || destroyPending}
            onClick={() =>
              onDelete(
                `Delete applicability row "${String(row.actionName ?? row.id)}" on "${String(row.objectKind)}:${String(row.objectType ?? "NULL")}"? This cannot be undone.`,
              )
            }
            size="sm"
            variant="outline"
            className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
          >
            Delete
          </Button>
        </>
      ) : resourceKey === "action-assignment-rules" ? (
        <Button
          disabled={missingDelete || destroyPending}
          onClick={() =>
            onDelete(
              `Delete assignment guardrail "${String(row.entityKind)} ${String(row.actionName)} ${String(row.objectKind)}:${String(row.objectType ?? "NULL")}"? This cannot be undone.`,
            )
          }
          size="sm"
          variant="outline"
          className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
        >
          Delete
        </Button>
      ) : resourceKey === "policies" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setPolicy(row))}
          onDelete={() =>
            onDelete("Delete this direct policy? This cannot be undone.")
          }
        />
      ) : (
        <>
          {!missingUpdate && (
            <Button size="sm" variant="outline">
              Edit
            </Button>
          )}
          <Button
            disabled={missingDelete || destroyPending}
            onClick={() =>
              onDelete(
                `Delete "${String(row.name ?? row.id)}"? This cannot be undone.`,
              )
            }
            size="sm"
            variant="destructive"
          >
            Delete
          </Button>
        </>
      )}
    </div>
  );
}
