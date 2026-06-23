"use client";

import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Braces,
  Building2,
  Clock,
  Database,
  Fingerprint,
  Gauge,
  GitBranch,
  KeyRound,
  ScrollText,
  Server,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { useTenant } from "@/components/app-shell/tenant-provider";
import {
  type ChartDatum,
  EntityKindDonut,
  ResourceKindBars,
  RiskBars,
} from "@/components/dashboard/dashboard-charts";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { graphqlClient } from "@/lib/graphql/client";
import { GLOBAL_TENANT } from "@/lib/tenant/context";

type Count = {
  total: number;
};

type CountWithItems<T> = Count & {
  items: T[];
};

type SummaryResponse = {
  tenants: Count;
  tenantsActive: Count;
  tenantsInactive: Count;
  tenantsFrozen: Count;
  entities: Count;
  entitiesActive: Count;
  entitiesInactive: Count;
  profiles: Count;
  profilesActive: Count;
  profilesDisabled: Count;
  groups: Count;
  groupsActive: Count;
  groupsInactive: Count;
  resources: Count;
  policies: Count;
  roles: Count;
  auditLogs: Count;
};

type EntityBreakdownResponse = {
  humans: Count;
  devices: Count;
  services: Count;
  workloads: Count;
  applications: Count;
};

type ResourceKindsResponse = {
  resources: CountWithItems<{ kind: string }>;
};

type RiskResponse = {
  orphanPolicies: unknown[];
  unprotectedResources: unknown[];
  expiringCredentials: unknown[];
  authzDenied: Count;
};

type PostureResponse = {
  policies: CountWithItems<{
    permissionBlock: { effect: string; scopeKind: string };
  }>;
  authzAllowed: Count;
  authzDenied: Count;
};

type ProductionPostureResponse = {
  systemStatus: {
    dbPool: {
      maxConnections: number;
      size: number;
      idle: number;
    };
    signingKeyState: {
      plaintextCount: number;
      plaintextAllowed: boolean;
    } | null;
    auditRetention: {
      enabled: boolean;
      days: number;
    };
    rateLimits: {
      enabled: boolean;
    };
  };
  expiringCredentials: unknown[];
  authzDenied: Count;
};

const SUMMARY_QUERY = `
  query DashboardSummary {
    tenants(limit: 1, offset: 0) { total }
    tenantsActive: tenants(status: active, limit: 1, offset: 0) { total }
    tenantsInactive: tenants(status: inactive, limit: 1, offset: 0) { total }
    tenantsFrozen: tenants(status: frozen, limit: 1, offset: 0) { total }
    entities(limit: 1, offset: 0) { total }
    entitiesActive: entities(status: active, limit: 1, offset: 0) { total }
    entitiesInactive: entities(status: inactive, limit: 1, offset: 0) { total }
    profiles(limit: 1, offset: 0) { total }
    profilesActive: profiles(status: "active", limit: 1, offset: 0) { total }
    profilesDisabled: profiles(status: "disabled", limit: 1, offset: 0) { total }
    groups(limit: 1, offset: 0) { total }
    groupsActive: groups(status: active, limit: 1, offset: 0) { total }
    groupsInactive: groups(status: inactive, limit: 1, offset: 0) { total }
    resources(limit: 1, offset: 0) { total }
    policies: directPolicies(limit: 1, offset: 0) { total }
    roles(limit: 1, offset: 0) { total }
    auditLogs(limit: 1, offset: 0) { total }
  }
`;

const ENTITY_BREAKDOWN_QUERY = `
  query DashboardEntityBreakdown {
    humans: entities(kind: human, limit: 1, offset: 0) { total }
    devices: entities(kind: device, limit: 1, offset: 0) { total }
    services: entities(kind: service, limit: 1, offset: 0) { total }
    workloads: entities(kind: workload, limit: 1, offset: 0) { total }
    applications: entities(kind: application, limit: 1, offset: 0) { total }
  }
`;

const RESOURCE_KINDS_QUERY = `
  query DashboardResourceKinds {
    resources(limit: 200, offset: 0) {
      total
      items { kind }
    }
  }
`;

const RISK_QUERY = `
  query DashboardRisk {
    orphanPolicies(limit: 50, offset: 0) { id }
    unprotectedResources(limit: 50, offset: 0) { id }
    expiringCredentials(days: 30, limit: 50, offset: 0) { id }
    authzDenied: auditLogs(event: "authz.check", outcome: deny, limit: 1, offset: 0) { total }
  }
`;

const POSTURE_QUERY = `
  query DashboardPosture {
    policies: directPolicies(limit: 200, offset: 0) {
      total
      items {
        permissionBlock {
          effect
          scopeKind: scopeMode
        }
      }
    }
    authzAllowed: auditLogs(event: "authz.check", outcome: allow, limit: 1, offset: 0) { total }
    authzDenied: auditLogs(event: "authz.check", outcome: deny, limit: 1, offset: 0) { total }
  }
`;

const PRODUCTION_POSTURE_QUERY = `
  query DashboardProductionPosture {
    systemStatus {
      dbPool { maxConnections size idle }
      signingKeyState { plaintextCount plaintextAllowed }
      auditRetention { enabled days }
      rateLimits { enabled }
    }
    expiringCredentials(days: 30, limit: 50, offset: 0) { id }
    authzDenied: auditLogs(event: "authz.check", outcome: deny, limit: 1, offset: 0) { total }
  }
`;

const ENTITY_KIND_COLORS = [
  "oklch(0.72 0.15 164)", // human    – green (on-theme)
  "oklch(0.70 0.14 220)", // device   – blue
  "oklch(0.68 0.13 290)", // service  – purple
  "oklch(0.74 0.15 55)", // workload – amber
  "oklch(0.71 0.14 195)", // application – teal
];
const SUMMARY_SKELETONS = [
  "health",
  "entities",
  "tenants",
  "resources",
  "policies",
  "roles",
  "audit",
  "credentials",
];
const TABLE_SKELETONS = ["row-1", "row-2", "row-3", "row-4", "row-5"];
const COMPACT_SKELETONS = ["metric-1", "metric-2", "metric-3", "metric-4"];

export function DashboardOverview() {
  return (
    <div className="grid gap-6">
      <SummaryCards />
      <ProductionPostureCards />

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <EntityMixCard />
        <ResourceKindsCard />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <RiskCard />
        <PostureCard />
      </section>
    </div>
  );
}

function ProductionPostureCards() {
  const query = useQuery({
    queryKey: ["dashboard", "production-posture"],
    queryFn: ({ signal }) =>
      graphqlClient<ProductionPostureResponse>({
        query: PRODUCTION_POSTURE_QUERY,
        signal,
      }),
  });

  if (query.isLoading) {
    return (
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {["db", "keys", "audit", "rate", "credentials", "denies"].map(
          (item) => (
            <Card key={item}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-28" />
                <Skeleton className="mt-3 h-7 w-20" />
              </CardHeader>
            </Card>
          ),
        )}
      </section>
    );
  }

  if (query.error) {
    return (
      <WidgetError
        error={query.error}
        title="Production posture is unavailable"
      />
    );
  }

  const cards = buildProductionPostureCards(query.data);

  return (
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {cards.map((card) => (
        <Card key={card.label}>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-2">
                <card.icon className="size-4" />
                {card.label}
              </span>
              <Badge variant={card.risk ? "destructive" : "secondary"}>
                {card.status}
              </Badge>
            </CardDescription>
            <CardTitle className="text-xl tabular-nums">{card.value}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {card.description}
          </CardContent>
        </Card>
      ))}
    </section>
  );
}

function SummaryCards() {
  const { selection } = useTenant();
  const isGlobal = selection.id === GLOBAL_TENANT;

  const query = useQuery({
    queryKey: ["dashboard", "summary"],
    queryFn: ({ signal }) =>
      graphqlClient<SummaryResponse>({ query: SUMMARY_QUERY, signal }),
  });

  if (query.isLoading) {
    const skeletonCount = isGlobal ? 8 : 7;
    return (
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {SUMMARY_SKELETONS.slice(0, skeletonCount).map((id) => (
          <Card key={id}>
            <CardHeader className="pb-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="mt-3 h-8 w-20" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-4 w-full" />
            </CardContent>
          </Card>
        ))}
      </section>
    );
  }

  if (query.error) {
    return (
      <WidgetError error={query.error} title="Summary data is unavailable" />
    );
  }

  const cards = buildSummaryCards(query.data, isGlobal);

  return (
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <Link key={card.label} href={card.href}>
          <Card className="h-full transition-colors hover:bg-accent/50">
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between gap-2">
                <span>{card.label}</span>
                <card.icon className="size-4 text-muted-foreground" />
              </CardDescription>
              <CardTitle className="text-2xl tabular-nums">
                {formatNumber(card.value)}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              {card.status ? (
                <div className="flex flex-wrap gap-1.5">
                  {card.status.map((s) => (
                    <span
                      key={s.label}
                      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium tabular-nums ${
                        s.label === "active"
                          ? "bg-green-500/15 text-green-700 dark:text-green-400"
                          : "bg-red-500/15 text-red-700 dark:text-red-400"
                      }`}
                    >
                      {formatNumber(s.value)} {s.label}
                    </span>
                  ))}
                </div>
              ) : (
                card.description
              )}
            </CardContent>
          </Card>
        </Link>
      ))}
    </section>
  );
}

function EntityMixCard() {
  const query = useQuery({
    queryKey: ["dashboard", "entity-breakdown"],
    queryFn: ({ signal }) =>
      graphqlClient<EntityBreakdownResponse>({
        query: ENTITY_BREAKDOWN_QUERY,
        signal,
      }),
  });

  const entityKindData = buildEntityKindData(query.data);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Entity Mix</CardTitle>
        <CardDescription>
          Breakdown of principals by entity kind.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <WidgetBody query={query} skeleton="chart">
          <EntityKindDonut data={entityKindData} />
          <MetricList data={entityKindData} />
        </WidgetBody>
      </CardContent>
    </Card>
  );
}

function RiskCard() {
  const query = useQuery({
    queryKey: ["dashboard", "risk"],
    queryFn: ({ signal }) =>
      graphqlClient<RiskResponse>({ query: RISK_QUERY, signal }),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attention Needed</CardTitle>
        <CardDescription>
          Guardrail and hygiene checks already exposed by Atom.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <WidgetBody query={query} skeleton="chart">
          <RiskBars data={buildRiskData(query.data)} />
        </WidgetBody>
      </CardContent>
    </Card>
  );
}

function ResourceKindsCard() {
  const query = useQuery({
    queryKey: ["dashboard", "resource-kinds"],
    queryFn: ({ signal }) =>
      graphqlClient<ResourceKindsResponse>({
        query: RESOURCE_KINDS_QUERY,
        signal,
      }),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Resource Kinds</CardTitle>
        <CardDescription>
          Top resource kinds from the first 200 visible resources.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <WidgetBody query={query} skeleton="chart">
          <ResourceKindBars
            data={topCounts(query.data?.resources.items ?? [], "kind", 6)}
          />
        </WidgetBody>
      </CardContent>
    </Card>
  );
}

function PostureCard() {
  const query = useQuery({
    queryKey: ["dashboard", "posture"],
    queryFn: ({ signal }) =>
      graphqlClient<PostureResponse>({ query: POSTURE_QUERY, signal }),
  });
  const policyBreakdown = policyStats(query.data?.policies.items ?? []);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Authorization Posture</CardTitle>
        <CardDescription>
          Policy and authorization signal available from current queries.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <WidgetBody query={query} skeleton="compact">
          <div className="grid gap-4">
            <div className="grid grid-cols-2 gap-3">
              <MiniMetric
                label="Allow policies"
                value={policyBreakdown.allow}
              />
              <MiniMetric label="Deny policies" value={policyBreakdown.deny} />
              <MiniMetric
                label="Authorization allowed"
                value={query.data?.authzAllowed.total ?? 0}
              />
              <MiniMetric
                label="Authorization denied"
                value={query.data?.authzDenied.total ?? 0}
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {policyBreakdown.scopes.map((scope) => (
                <Badge key={scope.label} variant="secondary">
                  {scope.label}: {formatNumber(scope.value)}
                </Badge>
              ))}
            </div>
          </div>
        </WidgetBody>
      </CardContent>
    </Card>
  );
}

function WidgetBody({
  children,
  query,
  skeleton,
}: {
  children: React.ReactNode;
  query: { isLoading: boolean; error: Error | null };
  skeleton: "chart" | "compact" | "table";
}) {
  if (query.isLoading) {
    return <WidgetSkeleton variant={skeleton} />;
  }

  if (query.error) {
    return <InlineError error={query.error} />;
  }

  return children;
}

function WidgetSkeleton({
  variant,
}: {
  variant: "chart" | "compact" | "table";
}) {
  if (variant === "table") {
    return (
      <div className="grid gap-3">
        {TABLE_SKELETONS.map((item) => (
          <Skeleton key={item} className="h-9 w-full" />
        ))}
      </div>
    );
  }

  if (variant === "compact") {
    return (
      <div className="grid gap-3">
        <div className="grid grid-cols-2 gap-3">
          {COMPACT_SKELETONS.map((item) => (
            <Skeleton key={item} className="h-20 w-full" />
          ))}
        </div>
        <Skeleton className="h-8 w-full" />
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      <Skeleton className="h-72 w-full" />
      <div className="grid gap-2 sm:grid-cols-2">
        <Skeleton className="h-5 w-full" />
        <Skeleton className="h-5 w-full" />
      </div>
    </div>
  );
}

function WidgetError({ error, title }: { error: Error; title: string }) {
  return (
    <Alert variant="destructive">
      <AlertTriangle />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{error.message}</AlertDescription>
    </Alert>
  );
}

function InlineError({ error }: { error: Error }) {
  return (
    <Alert variant="destructive">
      <AlertTriangle />
      <AlertTitle>Widget failed to load</AlertTitle>
      <AlertDescription>{error.message}</AlertDescription>
    </Alert>
  );
}

type CardDef = {
  label: string;
  value: number;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  status: Array<{ label: string; value: number }> | null;
  description: string | null;
};

function buildSummaryCards(
  data: SummaryResponse | undefined,
  isGlobal: boolean,
): CardDef[] {
  const cards: CardDef[] = [];

  if (isGlobal) {
    cards.push({
      label: "Tenants",
      value: data?.tenants.total ?? 0,
      href: "/tenants",
      icon: Building2,
      status: [
        { label: "active", value: data?.tenantsActive.total ?? 0 },
        { label: "inactive", value: data?.tenantsInactive.total ?? 0 },
        { label: "frozen", value: data?.tenantsFrozen.total ?? 0 },
      ],
      description: null,
    });
  }

  cards.push(
    {
      label: "Entities",
      value: data?.entities.total ?? 0,
      href: "/entities",
      icon: Fingerprint,
      status: [
        { label: "active", value: data?.entitiesActive.total ?? 0 },
        { label: "disabled", value: data?.entitiesInactive.total ?? 0 },
      ],
      description: null,
    },
    {
      label: "Profiles",
      value: data?.profiles.total ?? 0,
      href: "/profiles",
      icon: Braces,
      status: [
        { label: "active", value: data?.profilesActive.total ?? 0 },
        { label: "inactive", value: data?.profilesDisabled.total ?? 0 },
      ],
      description: null,
    },
    {
      label: "Groups",
      value: data?.groups.total ?? 0,
      href: "/groups",
      icon: Users,
      status: [
        { label: "active", value: data?.groupsActive.total ?? 0 },
        { label: "inactive", value: data?.groupsInactive.total ?? 0 },
      ],
      description: null,
    },
    {
      label: "Resources",
      value: data?.resources.total ?? 0,
      href: "/resources",
      icon: Server,
      status: null,
      description: "Protected objects visible to this session.",
    },
    {
      label: "Direct Policies",
      value: data?.policies.total ?? 0,
      href: "/policies",
      icon: GitBranch,
      status: null,
      description: "Allow and deny bindings across scopes.",
    },
    {
      label: "Roles",
      value: data?.roles.total ?? 0,
      href: "/roles",
      icon: ShieldCheck,
      status: null,
      description: "Named collections of permission blocks.",
    },
    {
      label: "Audit Events",
      value: data?.auditLogs.total ?? 0,
      href: "/audit",
      icon: ScrollText,
      status: null,
      description: "Total events visible to this session.",
    },
  );

  return cards;
}

function buildEntityKindData(
  data: EntityBreakdownResponse | undefined,
): ChartDatum[] {
  const rows = [
    ["human", "Humans", data?.humans.total ?? 0],
    ["device", "Devices", data?.devices.total ?? 0],
    ["service", "Services", data?.services.total ?? 0],
    ["workload", "Workloads", data?.workloads.total ?? 0],
    ["application", "Applications", data?.applications.total ?? 0],
  ] as const;

  return rows.map(([, label, value], index) => ({
    label,
    value,
    fill: ENTITY_KIND_COLORS[index],
  }));
}

function buildRiskData(data: RiskResponse | undefined): ChartDatum[] {
  return [
    { label: "Orphan policies", value: data?.orphanPolicies.length ?? 0 },
    {
      label: "Unprotected resources",
      value: data?.unprotectedResources.length ?? 0,
    },
    {
      label: "Expiring credentials",
      value: data?.expiringCredentials.length ?? 0,
    },
    { label: "Authorization denied", value: data?.authzDenied.total ?? 0 },
  ];
}

function buildProductionPostureCards(
  data: ProductionPostureResponse | undefined,
) {
  const pool = data?.systemStatus.dbPool;
  const activeConnections = Math.max(0, (pool?.size ?? 0) - (pool?.idle ?? 0));
  const poolPressure =
    pool?.maxConnections && pool.maxConnections > 0
      ? Math.round((activeConnections / pool.maxConnections) * 100)
      : 0;
  const plaintextCount =
    data?.systemStatus.signingKeyState?.plaintextCount ?? 0;
  const plaintextAllowed =
    data?.systemStatus.signingKeyState?.plaintextAllowed ?? false;
  const auditEnabled = data?.systemStatus.auditRetention.enabled ?? false;
  const rateLimitsEnabled = data?.systemStatus.rateLimits.enabled ?? false;
  const expiringCredentials = data?.expiringCredentials.length ?? 0;
  const denied = data?.authzDenied.total ?? 0;

  return [
    {
      label: "DB pool pressure",
      value: `${poolPressure}%`,
      status: poolPressure >= 80 ? "high" : "ok",
      risk: poolPressure >= 80,
      description: `${activeConnections} active of ${pool?.maxConnections ?? 0} max connections.`,
      icon: Database,
    },
    {
      label: "Signing key risk",
      value: formatNumber(plaintextCount),
      status: plaintextCount > 0 || plaintextAllowed ? "review" : "ok",
      risk: plaintextCount > 0 || plaintextAllowed,
      description: plaintextAllowed
        ? "Plaintext fallback is enabled."
        : "Plaintext signing key rows.",
      icon: KeyRound,
    },
    {
      label: "Audit retention",
      value: `${data?.systemStatus.auditRetention.days ?? 0}d`,
      status: auditEnabled ? "on" : "off",
      risk: !auditEnabled,
      description: "Configured retention window.",
      icon: Clock,
    },
    {
      label: "Rate limits",
      value: rateLimitsEnabled ? "On" : "Off",
      status: rateLimitsEnabled ? "on" : "off",
      risk: !rateLimitsEnabled,
      description: "HTTP abuse controls.",
      icon: Gauge,
    },
    {
      label: "Expiring credentials",
      value: formatNumber(expiringCredentials),
      status: expiringCredentials > 0 ? "review" : "ok",
      risk: expiringCredentials > 0,
      description: "Credentials expiring within 30 days.",
      icon: ShieldAlert,
    },
    {
      label: "Recent authorization denies",
      value: formatNumber(denied),
      status: denied > 0 ? "watch" : "ok",
      risk: false,
      description: "Visible deny decisions in audit logs.",
      icon: AlertTriangle,
    },
  ];
}

function topCounts<T extends Record<string, unknown>>(
  items: T[],
  key: keyof T,
  limit: number,
): ChartDatum[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const value = String(item[key] ?? "unknown");
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }

  const rows = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));

  return rows.length ? rows : [{ label: "None", value: 0 }];
}

function policyStats(items: PostureResponse["policies"]["items"]) {
  const blocks = items.map((item) => item.permissionBlock);
  const allow = blocks.filter((block) => block.effect === "allow").length;
  const deny = blocks.filter((block) => block.effect === "deny").length;
  return {
    allow,
    deny,
    scopes: topCounts(blocks, "scopeKind", 5),
  };
}

function MetricList({ data }: { data: ChartDatum[] }) {
  return (
    <div className="mt-4 grid gap-2 sm:grid-cols-2">
      {data.map((item) => (
        <div
          key={item.label}
          className="flex items-center justify-between gap-2"
        >
          <span className="truncate text-sm text-muted-foreground">
            {item.label}
          </span>
          <span className="font-mono text-sm tabular-nums">
            {formatNumber(item.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-xl font-semibold tabular-nums">
        {formatNumber(value)}
      </div>
    </div>
  );
}

function formatNumber(value: number) {
  return new Intl.NumberFormat("en").format(value);
}
