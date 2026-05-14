import type { TENANT_STATUS_MUTATIONS } from "@/components/crud/table/constants";

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
