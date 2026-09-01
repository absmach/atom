import { ActionApplicabilityCreateForm } from "@/components/actions/action-create-form";
import {
  actionApplicabilityFormInitialValues,
  entityFormInitialValues,
  groupFormInitialValues,
  profileFormInitialValues,
  resourceFormInitialValues,
  roleFormInitialValues,
  tenantFormInitialValues,
} from "@/components/crud/table/initial-values";
import type { Row } from "@/components/crud/table/types";
import { EntityCreateForm } from "@/components/entities/entity-create-form";
import { GroupEditForm } from "@/components/groups/group-edit-form";
import { PolicyCreateForm } from "@/components/policy/policy-create-form";
import { ProfileEditForm } from "@/components/profiles/profile-edit-form";
import { ResourceCreateForm } from "@/components/resources/resource-create-form";
import { RoleCreateForm } from "@/components/roles/role-create-form";
import { TenantCreateForm } from "@/components/tenants/tenant-create-form";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

export type EditingRows = {
  tenant: Row | null;
  entity: Row | null;
  profile: Row | null;
  group: Row | null;
  resource: Row | null;
  role: Row | null;
  actionApplicability: Row | null;
  policy: Row | null;
};

export type EditingSetters = {
  setTenant: (row: Row | null) => void;
  setEntity: (row: Row | null) => void;
  setProfile: (row: Row | null) => void;
  setGroup: (row: Row | null) => void;
  setResource: (row: Row | null) => void;
  setRole: (row: Row | null) => void;
  setActionApplicability: (row: Row | null) => void;
  setPolicy: (row: Row | null) => void;
};

export function CrudEditSheets({
  editing,
  onRefresh,
  setters,
}: {
  editing: EditingRows;
  onRefresh: () => void;
  setters: EditingSetters;
}) {
  return (
    <>
      <Sheet
        open={Boolean(editing.tenant)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setTenant(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.tenant?.name ?? editing.tenant?.id ?? "tenant")}`}
            </SheetTitle>
            <SheetDescription>
              Update tenant basics, tags, and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.tenant ? (
              <TenantCreateForm
                key={String(editing.tenant.id)}
                tenant={tenantFormInitialValues(editing.tenant)}
                onCancel={() => setters.setTenant(null)}
                onCreated={() => {
                  setters.setTenant(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.entity)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setEntity(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.entity?.name ?? editing.entity?.id ?? "entity")}`}
            </SheetTitle>
            <SheetDescription>
              Update this entity&apos;s details, profile, and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.entity ? (
              <EntityCreateForm
                key={String(editing.entity.id)}
                entity={entityFormInitialValues(editing.entity)}
                onCancel={() => setters.setEntity(null)}
                onCreated={() => {
                  setters.setEntity(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.profile)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setProfile(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-3xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.profile?.displayName ?? editing.profile?.id ?? "profile")}`}
            </SheetTitle>
            <SheetDescription>
              Update this profile&apos;s display name, description, and status.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.profile ? (
              <ProfileEditForm
                key={String(editing.profile.id)}
                profile={profileFormInitialValues(editing.profile)}
                onCancel={() => setters.setProfile(null)}
                onSaved={() => {
                  setters.setProfile(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.group)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setGroup(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.group?.name ?? editing.group?.id ?? "group")}`}
            </SheetTitle>
            <SheetDescription>
              Update this group&apos;s name and description.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.group ? (
              <GroupEditForm
                key={String(editing.group.id)}
                group={groupFormInitialValues(editing.group)}
                onCancel={() => setters.setGroup(null)}
                onSaved={() => {
                  setters.setGroup(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.resource)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setResource(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.resource?.name ?? editing.resource?.id ?? "resource")}`}
            </SheetTitle>
            <SheetDescription>
              Update this resource&apos;s name and attributes.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.resource ? (
              <ResourceCreateForm
                key={String(editing.resource.id)}
                resource={resourceFormInitialValues(editing.resource)}
                onCancel={() => setters.setResource(null)}
                onSaved={() => {
                  setters.setResource(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.role)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setRole(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.role?.name ?? editing.role?.id ?? "role")}`}
            </SheetTitle>
            <SheetDescription>
              Update this role&apos;s name, description, and permission blocks.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.role ? (
              <RoleCreateForm
                key={String(editing.role.id)}
                role={roleFormInitialValues(editing.role)}
                onCancel={() => setters.setRole(null)}
                onSaved={() => {
                  setters.setRole(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.actionApplicability)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setActionApplicability(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-md!">
          <SheetHeader>
            <SheetTitle>
              {`Edit ${String(editing.actionApplicability?.actionName ?? editing.actionApplicability?.name ?? editing.actionApplicability?.id ?? "action applicability")}`}
            </SheetTitle>
            <SheetDescription>
              Update this action applicability row.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.actionApplicability ? (
              <ActionApplicabilityCreateForm
                key={String(editing.actionApplicability.id)}
                applicability={actionApplicabilityFormInitialValues(
                  editing.actionApplicability,
                )}
                onCancel={() => setters.setActionApplicability(null)}
                onSaved={() => {
                  setters.setActionApplicability(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>

      <Sheet
        open={Boolean(editing.policy)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setters.setPolicy(null);
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
          <SheetHeader>
            <SheetTitle>Edit direct policy</SheetTitle>
            <SheetDescription>
              Replace this direct policy with a new subject-to-permission-block
              grant.
            </SheetDescription>
          </SheetHeader>
          <div className="px-4 pb-4">
            {editing.policy ? (
              <PolicyCreateForm
                key={String(editing.policy.id)}
                initialPolicy={{
                  id: String(editing.policy.id ?? ""),
                  tenantId:
                    editing.policy.tenantId != null
                      ? String(editing.policy.tenantId)
                      : null,
                  subjectKind: String(editing.policy.subjectKind ?? "entity"),
                  subjectId: String(editing.policy.subjectId ?? ""),
                  permissionBlockId: String(
                    editing.policy.permissionBlockId ?? "",
                  ),
                }}
                onCancel={() => setters.setPolicy(null)}
                onSaved={() => {
                  setters.setPolicy(null);
                  onRefresh();
                }}
              />
            ) : null}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
