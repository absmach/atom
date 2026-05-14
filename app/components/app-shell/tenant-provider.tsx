"use client";

import * as React from "react";
import {
  GLOBAL_TENANT,
  TENANT_COOKIE,
  type TenantSelection,
} from "@/lib/tenant/context";

const GLOBAL_OPTION: TenantSelection = { id: GLOBAL_TENANT, name: "Global" };

type TenantCtx = {
  selection: TenantSelection;
  setTenant: (next: TenantSelection) => void;
};

export const TenantContext = React.createContext<TenantCtx>({
  selection: GLOBAL_OPTION,
  setTenant: () => {},
});

export function useTenant() {
  return React.useContext(TenantContext);
}

export function TenantProvider({ children }: { children: React.ReactNode }) {
  const [selection, setSelection] =
    React.useState<TenantSelection>(GLOBAL_OPTION);

  // Seed from cookie on mount — name will be resolved by TenantSwitcher once tenants load.
  React.useEffect(() => {
    const storedId = document.cookie
      .split("; ")
      .find((row) => row.startsWith(`${TENANT_COOKIE}=`))
      ?.split("=")[1];
    if (storedId && storedId !== GLOBAL_TENANT) {
      setSelection({ id: storedId, name: storedId });
    }
  }, []);

  function setTenant(next: TenantSelection) {
    setSelection(next);
    // biome-ignore lint/suspicious/noDocumentCookie: non-sensitive tenant context persisted for server-side query filtering.
    document.cookie = `${TENANT_COOKIE}=${next.id}; path=/; sameSite=lax`;
  }

  return (
    <TenantContext.Provider value={{ selection, setTenant }}>
      {children}
    </TenantContext.Provider>
  );
}
