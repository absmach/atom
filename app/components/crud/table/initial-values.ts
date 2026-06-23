import type { ActionApplicabilityFormInitialValues } from "@/components/actions/action-create-form";
import type { Row } from "@/components/crud/table/types";
import type { EntityFormInitialValues } from "@/components/entities/entity-create-form";
import type { GroupFormInitialValues } from "@/components/groups/group-edit-form";
import type { ProfileFormInitialValues } from "@/components/profiles/profile-edit-form";
import type { ResourceFormInitialValues } from "@/components/resources/resource-create-form";
import type { RoleFormInitialValues } from "@/components/roles/role-create-form";
import type { TenantFormInitialValues } from "@/components/tenants/tenant-create-form";

export function roleFormInitialValues(row: Row): RoleFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

export function actionApplicabilityFormInitialValues(
  row: Row,
): ActionApplicabilityFormInitialValues {
  return {
    id: String(row.id),
    actionId: typeof row.actionId === "string" ? row.actionId : "",
    actionName: typeof row.actionName === "string" ? row.actionName : "",
    objectKind: typeof row.objectKind === "string" ? row.objectKind : "",
    objectType: typeof row.objectType === "string" ? row.objectType : "",
  };
}

export function resourceFormInitialValues(row: Row): ResourceFormInitialValues {
  return {
    id: String(row.id),
    kind: typeof row.kind === "string" ? row.kind : "",
    name: typeof row.name === "string" ? row.name : "",
    alias: typeof row.alias === "string" ? row.alias : "",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    ownerId: typeof row.ownerId === "string" ? row.ownerId : "",
    attributes:
      row.attributes && typeof row.attributes === "object"
        ? row.attributes
        : {},
  };
}

export function groupFormInitialValues(row: Row): GroupFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    tenantId: typeof row.tenantId === "string" ? row.tenantId : "",
    parentId: typeof row.parentId === "string" ? row.parentId : "",
    description: typeof row.description === "string" ? row.description : "",
  };
}

export function profileFormInitialValues(row: Row): ProfileFormInitialValues {
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

export function entityFormInitialValues(row: Row): EntityFormInitialValues {
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
    alias: typeof row.alias === "string" ? row.alias : "",
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

export function tenantFormInitialValues(row: Row): TenantFormInitialValues {
  return {
    id: String(row.id),
    name: typeof row.name === "string" ? row.name : "",
    alias: typeof row.alias === "string" ? row.alias : "",
    tags: Array.isArray(row.tags) ? row.tags.map((tag) => String(tag)) : [],
    attributes:
      row.attributes && typeof row.attributes === "object"
        ? row.attributes
        : {},
  };
}
