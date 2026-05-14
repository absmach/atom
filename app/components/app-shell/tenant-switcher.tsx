"use client";

import { useQuery } from "@tanstack/react-query";
import { Building2, Check, ChevronsUpDown, Globe2 } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { useTenant } from "@/components/app-shell/tenant-provider";
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
  const { selection, setTenant } = useTenant();
  const router = useRouter();

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

  // Resolve the display name for the ID seeded from the cookie once tenants load.
  React.useEffect(() => {
    if (!data || selection.id === GLOBAL_TENANT) return;
    const match = options.find((o) => o.id === selection.id);
    if (match && match.name !== selection.name) setTenant(match);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, selection.id]);

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
                onClick={() => {
                  setTenant(option);
                  router.push("/dashboard");
                }}
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
