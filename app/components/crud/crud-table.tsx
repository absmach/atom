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
  singularize,
  tenantActionPastTense,
} from "@/components/crud/table/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/ui/data-table";
import { requireResource } from "@/lib/crud/resources";
import { graphqlClient } from "@/lib/graphql/client";

export type { CrudTableProps };

export function CrudTable({
  resourceKey,
  rows,
  total,
  page,
  limit,
  source,
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
  const [editingCapability, setEditingCapability] = React.useState<Row | null>(
    null,
  );

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

  const columns: ColumnDef<Row>[] = [
    ...resource.columns.map((col) => ({
      accessorKey: col.key,
      header: col.label,
      cell: ({ getValue }: { getValue: () => unknown }) =>
        renderCell(getValue(), col.key),
    })),
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }: { row: { original: Row } }) => (
        <TableRowActions
          destroyPending={destroy.isPending}
          entityStatusPending={entityStatus.isPending}
          onDelete={(label) => {
            if (window.confirm(label)) destroy.mutate(row.original);
          }}
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
    capability: editingCapability,
    policy: editingPolicy,
  };

  const editingSetters: EditingSetters = {
    setTenant: setEditingTenant,
    setEntity: setEditingEntity,
    setProfile: setEditingProfile,
    setGroup: setEditingGroup,
    setResource: setEditingResource,
    setRole: setEditingRole,
    setCapability: setEditingCapability,
    setPolicy: setEditingPolicy,
  };

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        limit={limit}
        noResultsMessage={`No ${resource.title.toLowerCase()} found.`}
        page={page}
        paramKey={resourceKey}
        searchPlaceholder={`Filter ${resource.title.toLowerCase()}...`}
        statusFilter={{
          enabled: resource.columns.some((column) => column.key === "status"),
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
  return (
    <div className="flex justify-end gap-2">
      <Button onClick={onInspect} size="sm" variant="outline">
        Inspect
      </Button>
      {resourceKey === "tenants" ? (
        <TenantActionButtons
          isPending={tenantStatusPending}
          onEdit={() => onEdit.setTenant(row)}
          onStatusChange={onTenantStatusChange}
          row={row}
        />
      ) : resourceKey === "entities" ? (
        <EntityActionButtons
          isPending={entityStatusPending}
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
              `Delete group "${String(row.name ?? row.id)}"? This cannot be undone.`,
            )
          }
        />
      ) : resourceKey === "resources" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setResource(row))}
          onDelete={() =>
            onDelete(
              `Delete resource "${String(row.name ?? row.id)}"? This cannot be undone.`,
            )
          }
        />
      ) : resourceKey === "roles" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setRole(row))}
          onDelete={() =>
            onDelete(
              `Delete role "${String(row.name ?? row.id)}"? This cannot be undone.`,
            )
          }
        />
      ) : resourceKey === "capabilities" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setCapability(row))}
          onDelete={() =>
            onDelete(
              `Delete capability "${String(row.name ?? row.id)}"? This cannot be undone.`,
            )
          }
        />
      ) : resourceKey === "policies" ? (
        <DeleteActionButtons
          isDestroyPending={destroyPending}
          onEdit={() => defer(() => onEdit.setPolicy(row))}
          onDelete={() =>
            onDelete("Delete this policy binding? This cannot be undone.")
          }
        />
      ) : (
        <>
          <Button disabled={missingUpdate} size="sm" variant="outline">
            Edit
          </Button>
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
