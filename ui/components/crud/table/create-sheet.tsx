import type { FormEvent } from "react";
import {
  ActionApplicabilityCreateForm,
  ActionCreateForm,
} from "@/components/actions/action-create-form";
import { FallbackCreateForm } from "@/components/crud/table/quick-create-form";
import { singularize } from "@/components/crud/table/utils";
import { EntityCreateForm } from "@/components/entities/entity-create-form";
import { ActionAssignmentRuleCreateForm } from "@/components/guardrails/action-assignment-rule-create-form";
import { PermissionBlockCreateForm } from "@/components/permission-blocks/permission-block-create-form";
import { PolicyCreateForm } from "@/components/policy/policy-create-form";
import { ProfileCreateForm } from "@/components/profiles/profile-create-form";
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
import type { CrudResource } from "@/lib/crud/resources";

export function CrudCreateSheet({
  createIsPending,
  onOpenChange,
  onRefresh,
  onSubmitFallback,
  open,
  resource,
}: {
  createIsPending: boolean;
  onOpenChange: (open: boolean) => void;
  onRefresh: () => void;
  onSubmitFallback: (event: FormEvent<HTMLFormElement>) => void;
  open: boolean;
  resource: CrudResource;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,64rem)]! sm:max-w-2xl!">
        <SheetHeader>
          <SheetTitle>{`Create ${singularize(resource.title)}`}</SheetTitle>
          <SheetDescription>
            Add the details for this {singularize(resource.title).toLowerCase()}
            .
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-4">
          {resource.key === "entities" ? (
            <EntityCreateForm
              onCancel={() => onOpenChange(false)}
              onCreated={onRefresh}
            />
          ) : null}
          {resource.key === "profiles" ? (
            <ProfileCreateForm
              onCancel={() => onOpenChange(false)}
              onCreated={onRefresh}
            />
          ) : null}
          {resource.key === "tenants" ? (
            <TenantCreateForm
              onCancel={() => onOpenChange(false)}
              onCreated={onRefresh}
            />
          ) : null}
          {resource.key === "resources" ? (
            <ResourceCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "roles" ? (
            <RoleCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "permission-blocks" ? (
            <PermissionBlockCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "actions" ? (
            <ActionCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "action-applicability" ? (
            <ActionApplicabilityCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "action-assignment-rules" ? (
            <ActionAssignmentRuleCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {resource.key === "policies" ? (
            <PolicyCreateForm
              onCancel={() => onOpenChange(false)}
              onSaved={onRefresh}
            />
          ) : null}
          {usesFallbackCreateForm(resource.key) ? (
            <FallbackCreateForm
              formAttributes={resource.formAttributes}
              isPending={createIsPending}
              resourceKey={resource.key}
              onSubmit={onSubmitFallback}
            />
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function usesFallbackCreateForm(resourceKey: string) {
  return ![
    "entities",
    "profiles",
    "tenants",
    "resources",
    "roles",
    "permission-blocks",
    "actions",
    "action-applicability",
    "action-assignment-rules",
    "policies",
  ].includes(resourceKey);
}
