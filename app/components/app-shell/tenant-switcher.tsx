"use client";

import { useQuery } from "@tanstack/react-query";
import { Building2, Check, ChevronsUpDown, Globe2 } from "lucide-react";
import * as React from "react";

import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { graphqlClient } from "@/lib/graphql/client";
import {
  GLOBAL_TENANT,
  type TenantSelection,
  tenantLabel,
} from "@/lib/tenant/context";

const GLOBAL_OPTION: TenantSelection = { id: GLOBAL_TENANT, name: "Global" };

const TENANTS_QUERY = `
  query TenantSwitcher {
    tenants(limit: 100, offset: 0) {
      items { id name route }
    }
  }
`;

type TenantsData = {
  tenants: { items: { id: string; name: string; route: string | null }[] };
};

export function TenantSwitcher() {
  const { isMobile } = useSidebar();
  const [selection, setSelection] =
    React.useState<TenantSelection>(GLOBAL_OPTION);

  const { data } = useQuery({
    queryKey: ["tenant-switcher"],
    queryFn: ({ signal }) =>
      graphqlClient<TenantsData>({ query: TENANTS_QUERY, signal }),
    staleTime: 60_000,
  });

  const tenantOptions: TenantSelection[] = (data?.tenants.items ?? []).map(
    (t) => ({ id: t.id, name: t.name }),
  );
  const options = [GLOBAL_OPTION, ...tenantOptions];

  React.useEffect(() => {
    const stored = window.localStorage.getItem("atom.tenant");
    if (!stored) return;
    const match = options.find((o) => o.id === stored);
    if (match) setSelection(match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  function selectTenant(next: TenantSelection) {
    setSelection(next);
    window.localStorage.setItem("atom.tenant", next.id);
    // biome-ignore lint/suspicious/noDocumentCookie: non-sensitive tenant context is intentionally mirrored for route continuity.
    document.cookie = `atom_tenant=${next.id}; path=/; sameSite=lax`;
  }

  const Icon = selection.id === GLOBAL_TENANT ? Globe2 : Building2;
  const label = tenantLabel(selection);
  const badgeLabel = selection.id === GLOBAL_TENANT ? "platform" : "tenant";

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              tooltip={label}
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Icon className="shrink-0" />
              <span className="flex-1 truncate">{label}</span>
              <Badge
                variant="secondary"
                className="text-[0.68rem] group-data-[collapsible=icon]:hidden"
              >
                {badgeLabel}
              </Badge>
              <ChevronsUpDown className="ml-auto shrink-0 group-data-[collapsible=icon]:hidden" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-56"
            side={isMobile ? "bottom" : "right"}
            align="start"
            sideOffset={4}
          >
            <DropdownMenuLabel>Tenant context</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {options.map((option) => (
              <DropdownMenuItem
                key={option.id}
                onClick={() => selectTenant(option)}
              >
                <span className="flex-1">{option.name}</span>
                {selection.id === option.id ? (
                  <Check className="size-4" />
                ) : null}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
