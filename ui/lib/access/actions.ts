export type ActionApplicability = {
  objectKind: string;
  objectType?: string | null;
};

export type ActionLike = {
  name: string;
  applicability?: ActionApplicability[] | null;
};

export type ActionTarget = {
  objectKind: string;
  objectType?: string | null;
};

export const ACTION_APPLICABILITY_OPTIONS = [
  { label: "Tenant", objectKind: "tenant", objectType: null },
  { label: "Human users", objectKind: "entity", objectType: "entity:human" },
  {
    label: "Devices / clients",
    objectKind: "entity",
    objectType: "entity:device",
  },
  { label: "Services", objectKind: "entity", objectType: "entity:service" },
  { label: "Workloads", objectKind: "entity", objectType: "entity:workload" },
  {
    label: "Applications",
    objectKind: "entity",
    objectType: "entity:application",
  },
  { label: "Channels", objectKind: "resource", objectType: "resource:channel" },
  { label: "Rules", objectKind: "resource", objectType: "resource:rule" },
  { label: "Reports", objectKind: "resource", objectType: "resource:report" },
  { label: "Alarms", objectKind: "resource", objectType: "resource:alarm" },
  { label: "Groups", objectKind: "group", objectType: null },
  { label: "Roles", objectKind: "role", objectType: null },
  { label: "Assignments / policies", objectKind: "policy", objectType: null },
  { label: "Credentials", objectKind: "credential", objectType: null },
  { label: "Audit logs", objectKind: "audit_log", objectType: null },
  { label: "Signing keys", objectKind: "signing_key", objectType: null },
] as const;

export function encodeApplicability(item: ActionApplicability) {
  return `${item.objectKind}|${item.objectType ?? ""}`;
}

export function decodeApplicability(value: string): ActionApplicability {
  const [objectKind, objectType = ""] = value.split("|", 2);
  return { objectKind, objectType: objectType || null };
}

export function applicabilityValue(item: ActionApplicability) {
  return item.objectType ?? item.objectKind;
}

export function applicabilityValues(action: ActionLike) {
  return (action.applicability ?? []).map(applicabilityValue);
}

export function applicabilityLabel(action: ActionLike) {
  const values = applicabilityValues(action);
  return values.length > 0 ? values.join(", ") : "Not assigned to objects";
}

export function actionLabel(action: ActionLike) {
  const suffix = applicabilityValues(action);
  return suffix.length > 0
    ? `${action.name} (${suffix.join(", ")})`
    : action.name;
}

export function actionAppliesToTarget(
  action: ActionLike,
  target: ActionTarget | null,
) {
  if (!target) return true;
  return (action.applicability ?? []).some(
    (item) =>
      item.objectKind === target.objectKind &&
      (!target.objectType ||
        !item.objectType ||
        item.objectType === target.objectType),
  );
}

export function actionTargetFromRoleScope(
  scopeKind: string | null | undefined,
  scopeRef: string | null | undefined,
): ActionTarget | null {
  if (!scopeKind || scopeKind === "platform" || scopeKind === "tenant") {
    return null;
  }
  if (scopeKind === "object_kind") {
    return scopeRef ? { objectKind: scopeRef } : null;
  }
  if (scopeKind === "object_type") {
    return targetFromObjectType(scopeRef);
  }
  if (
    scopeKind === "group_direct_objects" ||
    scopeKind === "group_descendant_objects"
  ) {
    const [, objectKind, ...objectTypeParts] = (scopeRef ?? "").split(":");
    if (!objectKind || objectTypeParts.length === 0) return null;
    return {
      objectKind,
      objectType: `${objectKind}:${objectTypeParts.join(":")}`,
    };
  }
  if (
    scopeKind === "group_child_groups" ||
    scopeKind === "group_descendant_groups"
  ) {
    return { objectKind: "group" };
  }

  // Exact object scopes need object lookup to know their concrete type.
  return null;
}

function targetFromObjectType(value: string | null | undefined) {
  const [objectKind] = (value ?? "").split(":");
  if (!objectKind || !value?.includes(":")) return null;
  return { objectKind, objectType: value };
}
