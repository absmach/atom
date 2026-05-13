export const TENANT_COOKIE = "atom_tenant";
export const GLOBAL_TENANT = "global";

export type TenantSelection = {
  id: string;
  name: string;
};

export function tenantLabel(selection: TenantSelection | null) {
  return selection?.id && selection.id !== GLOBAL_TENANT
    ? selection.name
    : "Global";
}

export function tenantQueryValue(selection: TenantSelection | null) {
  return selection?.id && selection.id !== GLOBAL_TENANT ? selection.id : null;
}
