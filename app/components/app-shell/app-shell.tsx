"use client";

import {
  Activity,
  Braces,
  Building2,
  Code2,
  Fingerprint,
  GitBranch,
  Home,
  KeyRound,
  LayoutList,
  Link2,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type * as React from "react";
import { TenantSwitcher } from "@/components/app-shell/tenant-switcher";
import { UserNav } from "@/components/app-shell/user-nav";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { GLOBAL_TENANT } from "@/lib/tenant/context";
import { TenantProvider, useTenant } from "@/components/app-shell/tenant-provider";

type NavChild = { title: string; href: string; icon: React.ElementType };
type NavItem = {
  title: string;
  href: string;
  icon: React.ElementType;
  children?: NavChild[];
};

const nav: NavItem[] = [
  { title: "Dashboard", href: "/dashboard", icon: Home },
  { title: "Tenants", href: "/tenants", icon: Building2 },
  { title: "Entities", href: "/entities", icon: Fingerprint },
  { title: "Profiles", href: "/profiles", icon: Braces },
  { title: "Groups", href: "/groups", icon: Users },
  { title: "Resources", href: "/resources", icon: Server },
  { title: "Roles", href: "/roles", icon: ShieldCheck },
  { title: "Capabilities", href: "/capabilities", icon: KeyRound },
  { title: "Policies", href: "/policies", icon: GitBranch },
  { title: "Authz", href: "/authz", icon: Activity },
  { title: "Audit", href: "/audit", icon: ScrollText },
  {
    title: "Developer",
    href: "/developer",
    icon: Code2,
    children: [
      { title: "Templates", href: "/developer/templates", icon: LayoutList },
      { title: "Endpoints", href: "/developer/endpoints", icon: Link2 },
    ],
  },
  { title: "Settings", href: "/settings", icon: Settings },
];

export function AppShell({
  children,
  entityName,
  entityKind,
}: {
  children: React.ReactNode;
  entityName: string;
  entityKind?: string;
}) {
  return (
    <TenantProvider>
      <SidebarProvider>
        <AppSidebar entityName={entityName} entityKind={entityKind} />
        <SidebarInset>
          <header className="flex h-12 shrink-0 items-center gap-2 px-3">
            <SidebarTrigger />
          </header>
          <main>
            <div className="mx-auto flex w-full max-w-400 flex-col gap-6 p-4 sm:p-6 lg:p-8">
              {children}
            </div>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </TenantProvider>
  );
}

function AppSidebar({
  entityName,
  entityKind,
}: {
  entityName: string;
  entityKind?: string;
}) {
  const pathname = usePathname();
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== GLOBAL_TENANT;
  const visibleNav = isTenantScoped
    ? nav.filter((item) => item.href !== "/tenants")
    : nav;

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              asChild
              tooltip="Atom"
              className="hover:bg-transparent active:bg-transparent"
            >
              <Link href="/dashboard">
                <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground text-sm font-bold">
                  A
                </div>
                <span className="text-lg font-bold">Atom</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarSeparator className="mb-2" />

        <SidebarGroup>
          <SidebarGroupContent>
            <TenantSwitcher />
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator className="mb-2" />

        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu className="space-y-4">
              {visibleNav.map((item) => {
                const active =
                  pathname === item.href ||
                  pathname.startsWith(`${item.href}/`);
                return (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      asChild
                      isActive={active && !item.children}
                      tooltip={item.title}
                      className="[&_svg]:size-5 data-active:bg-primary data-active:text-primary-foreground"
                    >
                      <Link href={item.href} className="flex flex-row gap-4">
                        <item.icon />
                        <span className="text-base">{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                    {item.children && active ? (
                      <SidebarMenuSub>
                        {item.children.map((child) => (
                          <SidebarMenuSubItem key={child.href}>
                            <SidebarMenuSubButton
                              asChild
                              isActive={pathname === child.href}
                            >
                              <Link
                                href={child.href}
                                className="flex flex-row gap-2"
                              >
                                <child.icon className="size-4" />
                                <span>{child.title}</span>
                              </Link>
                            </SidebarMenuSubButton>
                          </SidebarMenuSubItem>
                        ))}
                      </SidebarMenuSub>
                    ) : null}
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <UserNav entityName={entityName} entityKind={entityKind} />
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}
