import type { TENANT_STATUS_MUTATIONS } from "@/components/crud/table/constants";
import type { Row } from "@/components/crud/table/types";

export function isDeletedRow(row: Row) {
  return Boolean(row.deletedAt) || String(row.status ?? "") === "deleted";
}

/**
 * A row is "config-managed" when it was provisioned from the Atom bootstrap
 * YAML file. The API rejects update/delete/restore on these rows with 409
 * conflict, so the UI hides mutation buttons — see
 * `components/crud/managed-by-badge.tsx` for the shared badge.
 */
export function isConfigManagedRow(row: Row) {
  return String(row.managedBy ?? "") === "config";
}

export function tenantActionPastTense(
  action: keyof typeof TENANT_STATUS_MUTATIONS,
) {
  switch (action) {
    case "enable":
      return "enabled";
    case "disable":
      return "disabled";
    case "freeze":
      return "frozen";
  }
}

export function singularize(title: string) {
  if (title.endsWith("ies")) return `${title.slice(0, -3)}y`;
  if (title.endsWith("s")) return title.slice(0, -1);
  return title;
}

export function defer(callback: () => void) {
  window.setTimeout(callback, 0);
}
