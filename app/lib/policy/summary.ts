export type PolicyDraft = {
  effect: "allow" | "deny";
  subjectKind: "entity" | "group";
  subjectName?: string;
  grantKind: "capability" | "role";
  grantName?: string;
  scopeKind: "platform" | "tenant" | "object_kind" | "object_type" | "object";
  scopeRef?: string;
  conditions: Array<{ path: string; operator: "equals"; value: string }>;
};

export function summarizePolicy(policy: PolicyDraft) {
  const effect = policy.effect === "allow" ? "Allow" : "Deny";
  const subject =
    policy.subjectName ||
    `${policy.subjectKind === "group" ? "members of selected group" : "selected entity"}`;
  const grant = policy.grantName || `selected ${policy.grantKind}`;
  const scope = scopeSummary(policy.scopeKind, policy.scopeRef);
  const conditions = policy.conditions
    .filter((condition) => condition.path && condition.value)
    .map((condition) => `${condition.path}=${condition.value}`)
    .join(" and ");

  return `${effect} ${subject} to ${grant} on ${scope}${conditions ? ` where ${conditions}` : ""}.`;
}

export function scopeSummary(kind: PolicyDraft["scopeKind"], ref?: string) {
  switch (kind) {
    case "platform":
      return "the entire platform";
    case "tenant":
      return ref ? `tenant ${ref}` : "the selected tenant";
    case "object_kind":
      return ref ? `all ${ref} objects` : "all objects of a kind";
    case "object_type":
      return ref ? `all ${ref} resources` : "all objects of a type";
    case "object":
      return ref ? `object ${ref}` : "a specific object";
  }
}
