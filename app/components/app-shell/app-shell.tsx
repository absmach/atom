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
  Link2,
  ScrollText,
  Server,
  ShieldCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type * as React from "react";
import { Fragment } from "react";
import {
  TenantProvider,
  useTenant,
} from "@/components/app-shell/tenant-provider";
import { TenantSwitcher } from "@/components/app-shell/tenant-switcher";
import { UserNav } from "@/components/app-shell/user-nav";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { GLOBAL_TENANT } from "@/lib/tenant/context";

type NavItem = {
  title: string;
  href: string;
  icon: React.ElementType;
};
type NavSection = {
  title: string;
  items: NavItem[];
};

const navSections: NavSection[] = [
  {
    title: "Overview",
    items: [
      { title: "Dashboard", href: "/dashboard", icon: Home },
      { title: "Tenants", href: "/tenants", icon: Building2 },
    ],
  },
  {
    title: "Identity & Access",
    items: [
      { title: "Entities", href: "/entities", icon: Fingerprint },
      { title: "Profiles", href: "/profiles", icon: Braces },
      { title: "Groups", href: "/groups", icon: Users },
      { title: "Resources", href: "/resources", icon: Server },
      { title: "Roles", href: "/roles", icon: ShieldCheck },
      { title: "Capabilities", href: "/capabilities", icon: KeyRound },
      { title: "Policies", href: "/policies", icon: GitBranch },
      { title: "Authz", href: "/authz", icon: Activity },
      { title: "Audit", href: "/audit", icon: ScrollText },
    ],
  },
  {
    title: "Developer",
    items: [
      { title: "Endpoints", href: "/endpoints", icon: Link2 },
      { title: "Playground", href: "/playground", icon: Code2 },
    ],
  },
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
  const visibleSections = navSections
    .map((section) => ({
      ...section,
      items: isTenantScoped
        ? section.items.filter((item) => item.href !== "/tenants")
        : section.items,
    }))
    .filter((section) => section.items.length > 0);

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

        {visibleSections.map((section, index) => (
          <Fragment key={section.title}>
            {index > 0 ? <SidebarSeparator /> : null}
            <SidebarGroup>
              <SidebarGroupLabel>{section.title}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu className="space-y-2">
                  {section.items.map((item) => {
                    const active =
                      pathname === item.href ||
                      pathname.startsWith(`${item.href}/`);
                    return (
                      <SidebarMenuItem key={item.href}>
                        <SidebarMenuButton
                          asChild
                          isActive={active}
                          tooltip={item.title}
                          className="data-active:bg-primary data-active:text-primary-foreground"
                        >
                          <Link href={item.href}>
                            <item.icon />
                            <span>{item.title}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </Fragment>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <UserNav entityName={entityName} entityKind={entityKind} />
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}
