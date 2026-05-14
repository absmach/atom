"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import {
  CapabilityCreateForm,
  type CapabilityFormInitialValues,
} from "@/components/capabilities/capability-create-form";
import { CapabilityInspectDetails } from "@/components/capabilities/capability-inspect-details";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { EntityAuditLog } from "@/components/entities/entity-audit-log";
import {
  EntityCreateForm,
  type EntityFormInitialValues,
} from "@/components/entities/entity-create-form";
import { EntityCredentials } from "@/components/entities/entity-credentials";
import { EntityInspectDetails } from "@/components/entities/entity-inspect-details";
import {
  GroupEditForm,
  type GroupFormInitialValues,
} from "@/components/groups/group-edit-form";
import { GroupInspectDetails } from "@/components/groups/group-inspect-details";
import { GroupMembersPanel } from "@/components/groups/group-members-panel";
import {
  PolicyCreateForm,
  type PolicyRow,
} from "@/components/policy/policy-create-form";
import { PolicyInspectDetails } from "@/components/policy/policy-inspect-details";
import { ProfileCreateForm } from "@/components/profiles/profile-create-form";
import {
  ProfileEditForm,
  type ProfileFormInitialValues,
} from "@/components/profiles/profile-edit-form";
import { ProfileInspectDetails } from "@/components/profiles/profile-inspect-details";
import {
  ResourceCreateForm,
  type ResourceFormInitialValues,
} from "@/components/resources/resource-create-form";
import { ResourceInspectDetails } from "@/components/resources/resource-inspect-details";
import { RoleCapabilitiesPanel } from "@/components/roles/role-capabilities-panel";
import {
  RoleCreateForm,
  type RoleFormInitialValues,
} from "@/components/roles/role-create-form";
import { RoleInspectDetails } from "@/components/roles/role-inspect-details";
import {
  TenantCreateForm,
  type TenantFormInitialValues,
} from "@/components/tenants/tenant-create-form";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/ui/data-table";
import { Input } from "@/components/ui/input";
import { JsonEditor } from "@/components/ui/json-editor";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { DisplayTags } from "@/components/view-tags";
import { requireResource } from "@/lib/crud/resources";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const TENANTS_QUERY = `
  query CrudTenants {
    tenants(limit: 100, offset: 0) {
      items { id name }
    }
  }
`;

const TENANT_STATUS_MUTATIONS = {
  enable: `mutation EnableTenant($id: ID!) { enableTenant(id: $id) { id status updatedAt } }`,
  disable: `mutation DisableTenant($id: ID!) { disableTenant(id: $id) { id status updatedAt } }`,
  freeze: `mutation FreezeTenant($id: ID!) { freezeTenant(id: $id) { id status updatedAt } }`,
} as const;

const ENTITY_STATUS_MUTATIONS = {
  enable: `mutation EnableEntity($id: ID!) { enableEntity(id: $id) { id status updatedAt } }`,
  disable: `mutation DisableEntity($id: ID!) { disableEntity(id: $id) { id status updatedAt } }`,
} as const;

const PROFILE_STATUS_MUTATION = `
  mutation UpdateProfileStatus($id: ID!, $input: UpdateProfileInput!) {
    updateProfile(id: $id, input: $input) { id status updatedAt }
  }
`;

type Row = Record<string, unknown>;

export type CrudTableProps = {
  resourceKey: string;
  rows: Row[];
  total: number;
  page: number;
  limit: number;
  source: "graphql" | "scaffold";
};

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
        <div className="flex justify-end gap-2">
          <Button
            onClick={() => defer(() => setInspected(row.original))}
            size="sm"
            variant="outline"
          >
            Inspect
          </Button>
          {resource.key === "tenants" ? (
            <TenantActionButtons
              isPending={tenantStatus.isPending}
              onEdit={() => setEditingTenant(row.original)}
              onStatusChange={(action) =>
                tenantStatus.mutate({ action, row: row.original })
              }
              row={row.original}
            />
          ) : resource.key === "entities" ? (
            <EntityActionButtons
              isPending={entityStatus.isPending}
              onEdit={() => defer(() => setEditingEntity(row.original))}
              onStatusChange={(action) =>
                entityStatus.mutate({ action, row: row.original })
              }
              row={row.original}
            />
          ) : resource.key === "profiles" ? (
            <ProfileActionButtons
              isPending={profileStatus.isPending}
              onEdit={() => defer(() => setEditingProfile(row.original))}
              onStatusChange={(status) =>
                profileStatus.mutate({ status, row: row.original })
              }
              row={row.original}
            />
          ) : resource.key === "groups" ? (
            <GroupActionButtons
              isDestroyPending={destroy.isPending}
              onEdit={() => defer(() => setEditingGroup(row.original))}
              onDelete={() => {
                if (
                  window.confirm(
                    `Delete group "${String(row.original.name ?? row.original.id)}"? This cannot be undone.`,
                  )
                ) {
                  destroy.mutate(row.original);
                }
              }}
            />
          ) : resource.key === "resources" ? (
            <ResourceActionButtons
              isDestroyPending={destroy.isPending}
              onEdit={() => defer(() => setEditingResource(row.original))}
              onDelete={() => {
                if (
                  window.confirm(
                    `Delete resource "${String(row.original.name ?? row.original.id)}"? This cannot be undone.`,
                  )
                ) {
                  destroy.mutate(row.original);
                }
              }}
            />
          ) : resource.key === "roles" ? (
            <RoleActionButtons
              isDestroyPending={destroy.isPending}
              onEdit={() => defer(() => setEditingRole(row.original))}
              onDelete={() => {
                if (
                  window.confirm(
                    `Delete role "${String(row.original.name ?? row.original.id)}"? This cannot be undone.`,
                  )
                ) {
                  destroy.mutate(row.original);
                }
              }}
            />
          ) : resource.key === "capabilities" ? (
            <CapabilityActionButtons
              isDestroyPending={destroy.isPending}
              onEdit={() => defer(() => setEditingCapability(row.original))}
              onDelete={() => {
                if (
                  window.confirm(
                    `Delete capability "${String(row.original.name ?? row.original.id)}"? This cannot be undone.`,
                  )
                ) {
                  destroy.mutate(row.original);
                }
              }}
            />
          ) : resource.key === "policies" ? (
            <PolicyActionButtons
              isDestroyPending={destroy.isPending}
              onEdit={() => defer(() => setEditingPolicy(row.original))}
              onDelete={() => {
                if (
                  window.confirm(
                    `Delete this policy binding? This cannot be undone.`,
                  )
                ) {
                  destroy.mutate(row.original);
                }
              }}
            />
          ) : (
            <>
              <Button
                disabled={Boolean(resource.missing.update)}
                size="sm"
                variant="outline"
              >
                Edit
              </Button>
              <Button
                disabled={Boolean(resource.missing.delete) || destroy.isPending}
                onClick={() => {
                  if (
                    window.confirm(
                      `Delete "${String(row.original.name ?? row.original.id)}"? This cannot be undone.`,
                    )
                  ) {
                    destroy.mutate(row.original);
                  }
                }}
                size="sm"
                variant="destructive"
              >
                Delete
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        limit={limit}
        noResultsMessage={`No ${resource.title.toLowerCase()} found.`}
        page={page}
        paramKey={resourceKey}
        searchPlaceholder={`Filter ${resource.title.toLowerCase()}…`}
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

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>{`Create ${singularize(resource.title)}`}</SheetTitle>
            <SheetDescription>
              Add the details for this{" "}
              {singularize(resource.title).toLowerCase()}.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {resource.key === "entities" ? (
              <EntityCreateForm
                onCancel={() => setOpen(false)}
                onCreated={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "profiles" ? (
              <ProfileCreateForm
                onCancel={() => setOpen(false)}
                onCreated={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "tenants" ? (
              <TenantCreateForm
                onCancel={() => setOpen(false)}
                onCreated={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "resources" ? (
              <ResourceCreateForm
                onCancel={() => setOpen(false)}
                onSaved={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "roles" ? (
              <RoleCreateForm
                onCancel={() => setOpen(false)}
                onSaved={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "capabilities" ? (
              <CapabilityCreateForm
                onCancel={() => setOpen(false)}
                onSaved={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key === "policies" ? (
              <PolicyCreateForm
                onCancel={() => setOpen(false)}
                onSaved={() => {
                  setOpen(false);
                  router.refresh();
                }}
              />
            ) : null}
            {resource.key !== "entities" &&
            resource.key !== "profiles" &&
            resource.key !== "tenants" &&
            resource.key !== "resources" &&
            resource.key !== "roles" &&
            resource.key !== "capabilities" &&
            resource.key !== "policies" ? (
              <form className="grid gap-4" onSubmit={submit}>
                {resource.key !== "tenants" ? (
                  <QuickField name="name" label="Name" required />
                ) : null}
                {resource.key === "groups" || resource.key === "roles" ? (
                  <QuickField name="description" label="Description" />
                ) : null}
                {resource.key !== "tenants" &&
                resource.key !== "capabilities" ? (
                  <TenantPickerField />
                ) : null}
                {resource.formAttributes ? (
                  <div className="grid gap-2">
                    <Label htmlFor="attributes">Attributes JSON</Label>
                    <Textarea
                      id="attributes"
                      name="attributes"
                      placeholder='{"env":"prod"}'
                    />
                  </div>
                ) : null}
                <Button type="submit" disabled={create.isPending}>
                  Save
                </Button>
              </form>
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingTenant)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingTenant(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingTenant?.name ?? editingTenant?.id ?? "tenant")}`}
            </SheetTitle>
            <SheetDescription>
              Update tenant basics, tags, and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingTenant ? (
              <TenantCreateForm
                key={String(editingTenant.id)}
                tenant={tenantFormInitialValues(editingTenant)}
                onCancel={() => setEditingTenant(null)}
                onCreated={() => {
                  setEditingTenant(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingEntity)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingEntity(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingEntity?.name ?? editingEntity?.id ?? "entity")}`}
            </SheetTitle>
            <SheetDescription>
              Update this entity&apos;s details, profile, and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingEntity ? (
              <EntityCreateForm
                key={String(editingEntity.id)}
                entity={entityFormInitialValues(editingEntity)}
                onCancel={() => setEditingEntity(null)}
                onCreated={() => {
                  setEditingEntity(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingProfile)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingProfile(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingProfile?.displayName ?? editingProfile?.id ?? "profile")}`}
            </SheetTitle>
            <SheetDescription>
              Update this profile&apos;s display name, description, and status.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingProfile ? (
              <ProfileEditForm
                key={String(editingProfile.id)}
                profile={profileFormInitialValues(editingProfile)}
                onCancel={() => setEditingProfile(null)}
                onSaved={() => {
                  setEditingProfile(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingGroup)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingGroup(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingGroup?.name ?? editingGroup?.id ?? "group")}`}
            </SheetTitle>
            <SheetDescription>
              Update this group&apos;s name and description.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingGroup ? (
              <GroupEditForm
                key={String(editingGroup.id)}
                group={groupFormInitialValues(editingGroup)}
                onCancel={() => setEditingGroup(null)}
                onSaved={() => {
                  setEditingGroup(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingResource)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingResource(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingResource?.name ?? editingResource?.id ?? "resource")}`}
            </SheetTitle>
            <SheetDescription>
              Update this resource&apos;s name and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingResource ? (
              <ResourceCreateForm
                key={String(editingResource.id)}
                resource={resourceFormInitialValues(editingResource)}
                onCancel={() => setEditingResource(null)}
                onSaved={() => {
                  setEditingResource(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingRole)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingRole(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingRole?.name ?? editingRole?.id ?? "role")}`}
            </SheetTitle>
            <SheetDescription>
              Update this role&apos;s name, description, and capabilities.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingRole ? (
              <RoleCreateForm
                key={String(editingRole.id)}
                role={roleFormInitialValues(editingRole)}
                onCancel={() => setEditingRole(null)}
                onSaved={() => {
                  setEditingRole(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingCapability)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingCapability(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editingCapability?.name ?? editingCapability?.id ?? "capability")}`}
            </SheetTitle>
            <SheetDescription>
              Update this capability&apos;s name, resource kind, and
              description.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingCapability ? (
              <CapabilityCreateForm
                key={String(editingCapability.id)}
                capability={capabilityFormInitialValues(editingCapability)}
                onCancel={() => setEditingCapability(null)}
                onSaved={() => {
                  setEditingCapability(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editingPolicy)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setEditingPolicy(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>Edit policy binding</SheetTitle>
            <SheetDescription>
              Modify this binding. The existing record will be replaced with the
              new one.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editingPolicy ? (
              <PolicyCreateForm
                key={String(editingPolicy.id)}
                initialPolicy={{
                  id: String(editingPolicy.id ?? ""),
                  effect: String(editingPolicy.effect ?? "allow"),
                  subjectKind: String(editingPolicy.subjectKind ?? "entity"),
                  subjectId: String(editingPolicy.subjectId ?? ""),
                  grantKind: String(editingPolicy.grantKind ?? "capability"),
                  grantId: String(editingPolicy.grantId ?? ""),
                  scopeKind: String(editingPolicy.scopeKind ?? "platform"),
                  scopeRef:
                    editingPolicy.scopeRef != null
                      ? String(editingPolicy.scopeRef)
                      : null,
                  conditions: editingPolicy.conditions,
                }}
                onCancel={() => setEditingPolicy(null)}
                onSaved={() => {
                  setEditingPolicy(null);
                  router.refresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(inspected)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setInspected(null);
        }}
      >
        <SheetContent
          className={
            resource.key === "profiles" ||
            resource.key === "tenants" ||
            resource.key === "entities" ||
            resource.key === "groups" ||
            resource.key === "roles" ||
            resource.key === "policies"
              ? "w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!"
              : "w-full overflow-y-auto sm:max-w-xl"
          }
        >
          <SheetHeader>
            <SheetTitle>
              {`Inspect ${String(inspected?.name ?? inspected?.displayName ?? inspected?.id ?? "")}`}
            </SheetTitle>
            <SheetDescription>
              Detail view for this {resource.title.toLowerCase()} item.
            </SheetDescription>
          </SheetHeader>
          <div className="grid min-w-0 gap-3 px-4 pb-4">
            {resource.key === "policies" ? (
              <PolicyInspectDetails row={inspected} />
            ) : resource.key === "profiles" ? (
              <ProfileInspectDetails row={inspected} />
            ) : resource.key === "entities" ? (
              <Tabs defaultValue="details">
                <TabsList className="mb-4">
                  <TabsTrigger value="details">Details</TabsTrigger>
                  <TabsTrigger value="audit">Audit Logs</TabsTrigger>
                </TabsList>
                <TabsContent value="details" className="grid gap-3">
                  <EntityInspectDetails row={inspected} />
                  {inspected?.id ? (
                    <EntityCredentials entityId={String(inspected.id)} />
                  ) : null}
                </TabsContent>
                <TabsContent value="audit">
                  {inspected?.id ? (
                    <EntityAuditLog entityId={String(inspected.id)} />
                  ) : null}
                </TabsContent>
              </Tabs>
            ) : resource.key === "groups" ? (
              <>
                <GroupInspectDetails row={inspected} />
                {inspected?.id ? (
                  <GroupMembersPanel groupId={String(inspected.id)} />
                ) : null}
              </>
            ) : resource.key === "resources" ? (
              <ResourceInspectDetails row={inspected} />
            ) : resource.key === "roles" ? (
              <>
                <RoleInspectDetails row={inspected} />
                {inspected?.id ? (
                  <RoleCapabilitiesPanel roleId={String(inspected.id)} />
                ) : null}
              </>
            ) : resource.key === "capabilities" ? (
              <CapabilityInspectDetails row={inspected} />
            ) : (
              <DetailFields row={inspected} />
            )}
            <Button onClick={() => setInspected(null)} variant="outline">
              Close
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}

function TenantActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (action: keyof typeof TENANT_STATUS_MUTATIONS) => void;
  row: Row;
}) {
  const status = String(row.status ?? "");

  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <>
          <Button
            disabled={isPending}
            onClick={() => onStatusChange("freeze")}
            size="sm"
            variant="outline"
            className="border-blue-500/50 text-blue-600 hover:bg-blue-500/10 hover:text-blue-600 dark:border-blue-500/40 dark:text-blue-400"
          >
            Freeze
          </Button>
          <Button
            disabled={isPending}
            onClick={() => onStatusChange("disable")}
            size="sm"
            variant="outline"
            className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
          >
            Disable
          </Button>
        </>
      ) : (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("enable")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      )}
    </>
  );
}

function EntityActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (action: keyof typeof ENTITY_STATUS_MUTATIONS) => void;
  row: Row;
}) {
  const status = String(row.status ?? "");
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("disable")}
          size="sm"
          variant="outline"
          className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
        >
          Disable
        </Button>
      ) : (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("enable")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      )}
    </>
  );
}

function ProfileActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (status: "active" | "disabled") => void;
  row: Row;
}) {
  const status = String(row.status ?? "");
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("disabled")}
          size="sm"
          variant="outline"
          className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
        >
          Disable
        </Button>
      ) : status === "disabled" || status === "deprecated" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("active")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      ) : null}
    </>
  );
}

function GroupActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}

function ResourceActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}

function RoleActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}

function CapabilityActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}

function PolicyActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}

function roleFormInitialValues(row: Row): RoleFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

function capabilityFormInitialValues(row: Row): CapabilityFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    resourceKind: typeof row.resourceKind === "string" ? row.resourceKind : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

function resourceFormInitialValues(row: Row): ResourceFormInitialValues {
  return {
    id: String(row.id),
    kind: typeof row.kind === "string" ? row.kind : "",
    name: typeof row.name === "string" ? row.name : "",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    ownerId: typeof row.ownerId === "string" ? row.ownerId : "",
    attributes:
      row.attributes && typeof row.attributes === "object"
        ? row.attributes
        : {},
  };
}

function groupFormInitialValues(row: Row): GroupFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

function profileFormInitialValues(row: Row): ProfileFormInitialValues {
  const PROFILE_STATUSES = ["active", "deprecated", "disabled"] as const;
  const rawStatus = typeof row.status === "string" ? row.status : "active";
  return {
    id: String(row.id),
    displayName: typeof row.displayName === "string" ? row.displayName : "",
    description: typeof row.description === "string" ? row.description : "",
    status: (PROFILE_STATUSES as readonly string[]).includes(rawStatus)
      ? (rawStatus as ProfileFormInitialValues["status"])
      : "active",
  };
}

function entityFormInitialValues(row: Row): EntityFormInitialValues {
  const ENTITY_KINDS = [
    "human",
    "device",
    "service",
    "workload",
    "application",
  ] as const;
  const rawKind = typeof row.kind === "string" ? row.kind : "human";
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    kind: (ENTITY_KINDS as readonly string[]).includes(rawKind)
      ? (rawKind as EntityFormInitialValues["kind"])
      : "human",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    profileId: typeof row.profileId === "string" ? row.profileId : "",
    profileVersionId:
      typeof row.profileVersionId === "string" ? row.profileVersionId : "",
    attributes:
      row.attributes && typeof row.attributes === "object"
        ? (row.attributes as Record<string, unknown>)
        : {},
  };
}

function tenantFormInitialValues(row: Row): TenantFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    route: typeof row.route === "string" ? row.route : "",
    tags: Array.isArray(row.tags) ? row.tags.map((tag) => String(tag)) : [],
    attributes:
      row.attributes && typeof row.attributes === "object"
        ? row.attributes
        : {},
  };
}

function tenantActionPastTense(action: keyof typeof TENANT_STATUS_MUTATIONS) {
  switch (action) {
    case "enable":
      return "enabled";
    case "disable":
      return "disabled";
    case "freeze":
      return "frozen";
  }
}

function JsonSchemaViewer({
  label,
  showLabel = true,
  value,
}: {
  label: string;
  showLabel?: boolean;
  value: unknown;
}) {
  const code = React.useMemo(() => JSON.stringify(value, null, 2), [value]);

  return (
    <div className="grid min-w-0 max-w-full gap-2">
      {showLabel ? (
        <div className="text-xs font-medium uppercase text-muted-foreground">
          {label}
        </div>
      ) : null}
      <JsonEditor value={code} className="[&_.cm-editor]:min-h-48" />
    </div>
  );
}

function DetailFields({ row }: { row: Row | null }) {
  return (
    <>
      {row
        ? Object.entries(row).map(([key, value]) => (
            <div
              className="grid gap-1 rounded-lg border bg-background p-3"
              key={key}
            >
              <div className="text-xs font-medium uppercase text-muted-foreground">
                {key}
              </div>
              <DetailFieldValue fieldKey={key} value={value} />
            </div>
          ))
        : null}
    </>
  );
}

function DetailFieldValue({
  fieldKey,
  value,
}: {
  fieldKey: string;
  value: unknown;
}) {
  if (fieldKey === "tags" && Array.isArray(value)) {
    return value.length ? (
      <DisplayTags
        className="max-w-full"
        tags={value.map((item) => String(item))}
      />
    ) : (
      <span className="text-muted-foreground">-</span>
    );
  }

  if (fieldKey === "attributes" && value && typeof value === "object") {
    return (
      <JsonSchemaViewer label="Attributes" showLabel={false} value={value} />
    );
  }

  if (
    isTimeColumn(fieldKey) &&
    typeof value === "string" &&
    isValidTime(value)
  ) {
    return (
      <DisplayTimeCell action={timeActionForColumn(fieldKey)} time={value} />
    );
  }

  return (
    <div className="wrap-break-word font-mono text-xs">
      {formatDetailValue(value)}
    </div>
  );
}

function QuickField({
  defaultValue,
  label,
  name,
  required,
}: {
  name: string;
  label: string;
  defaultValue?: string;
  required?: boolean;
}) {
  return (
    <div className="grid gap-2">
      <RequiredLabel htmlFor={name} required={required}>
        {label}
      </RequiredLabel>
      <Input
        defaultValue={defaultValue}
        id={name}
        name={name}
        required={required}
      />
    </div>
  );
}

function RequiredLabel({
  children,
  htmlFor,
  required,
}: {
  children: React.ReactNode;
  htmlFor: string;
  required?: boolean;
}) {
  return (
    <Label htmlFor={htmlFor}>
      {children}
      {required ? <span className="text-destructive"> *</span> : null}
    </Label>
  );
}

type TenantOption = { id: string; name: string };
type TenantsPickerData = { tenants: { items: TenantOption[] } };

function TenantPickerField() {
  const { data } = useQuery({
    queryKey: ["tenant-picker"],
    queryFn: ({ signal }) =>
      graphqlClient<TenantsPickerData>({ query: TENANTS_QUERY, signal }),
    staleTime: 60_000,
  });
  const tenants = data?.tenants.items ?? [];
  const [value, setValue] = React.useState("");

  return (
    <div className="grid gap-2">
      <Label htmlFor="tenantId">Tenant</Label>
      <input name="tenantId" type="hidden" value={value} />
      <select
        className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        id="tenantId"
        onChange={(e) => setValue(e.target.value)}
        value={value}
      >
        <option value="">— select tenant —</option>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </div>
  );
}

function renderCell(value: unknown, key?: string) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">-</span>;
  }
  if (
    key &&
    isTimeColumn(key) &&
    typeof value === "string" &&
    isValidTime(value)
  ) {
    return <DisplayTimeCell action={timeActionForColumn(key)} time={value} />;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-muted-foreground">-</span>;
    }
    return (
      <DisplayTags
        className="max-w-72"
        tags={value.map((item) => String(item))}
      />
    );
  }
  if (
    [
      "active",
      "inactive",
      "suspended",
      "allow",
      "deny",
      "disabled",
      "frozen",
      "deprecated",
    ].includes(String(value))
  ) {
    return <StatusBadge value={value} />;
  }
  if (key === "description") {
    return (
      <span className="block max-w-72 whitespace-normal wrap-break-word text-sm">
        {String(value)}
      </span>
    );
  }
  if (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      String(value),
    )
  ) {
    return (
      <span className="font-mono text-xs">{String(value).slice(0, 8)}…</span>
    );
  }
  if (String(value).length > 44) {
    return (
      <span className="font-mono text-xs">{String(value).slice(0, 8)}...</span>
    );
  }
  return <span>{String(value)}</span>;
}

function formatDetailValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

function isTimeColumn(key: string) {
  return (
    key === "createdAt" ||
    key === "updatedAt" ||
    key === "expiresAt" ||
    key === "lastUsedAt"
  );
}

function isValidTime(value: string) {
  return !Number.isNaN(Date.parse(value));
}

function timeActionForColumn(key: string) {
  switch (key) {
    case "updatedAt":
      return Action.Updated;
    case "expiresAt":
      return Action.Expired;
    case "lastUsedAt":
      return Action.LastUsed;
    case "createdAt":
      return Action.Created;
    default:
      return Action.Created;
  }
}

function singularize(title: string) {
  if (title.endsWith("ies")) return `${title.slice(0, -3)}y`;
  if (title.endsWith("s")) return title.slice(0, -1);
  return title;
}

function defer(callback: () => void) {
  window.setTimeout(callback, 0);
}
