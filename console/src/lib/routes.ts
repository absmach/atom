export const CONSOLE_BASE = "/graphql/console";

export type ConsoleRoute = {
  label: string;
  href: string;
  section: "Build" | "Operate" | "Secure" | "System";
};

export const CONSOLE_ROUTES: ConsoleRoute[] = [
  { label: "Dashboard", href: CONSOLE_BASE, section: "Build" },
  { label: "Endpoints", href: `${CONSOLE_BASE}/endpoints`, section: "Build" },
  { label: "Tenants", href: `${CONSOLE_BASE}/tenants`, section: "Operate" },
  { label: "Entities", href: `${CONSOLE_BASE}/entities`, section: "Operate" },
  { label: "Groups", href: `${CONSOLE_BASE}/groups`, section: "Operate" },
  { label: "Profiles", href: `${CONSOLE_BASE}/profiles`, section: "Operate" },
  { label: "Resources", href: `${CONSOLE_BASE}/resources`, section: "Secure" },
  { label: "Policies", href: `${CONSOLE_BASE}/policies`, section: "Secure" },
  { label: "Authz Tester", href: `${CONSOLE_BASE}/authz`, section: "Secure" },
  { label: "Playground", href: `${CONSOLE_BASE}/playground`, section: "System" },
  { label: "Explorer", href: `${CONSOLE_BASE}/explorer`, section: "System" },
  { label: "Settings", href: `${CONSOLE_BASE}/settings`, section: "System" },
];

export const TASK_ROUTES = CONSOLE_ROUTES.filter((route) => route.href !== CONSOLE_BASE);
