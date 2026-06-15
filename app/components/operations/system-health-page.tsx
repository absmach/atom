"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Database,
  Gauge,
  KeyRound,
  RadioTower,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
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

type ComponentStatus = "ok" | "disabled" | "degraded" | "error";

type ComponentCheck = {
  status: ComponentStatus;
  message: string;
};

type SystemStatus = {
  status: ComponentStatus;
  httpReady: ComponentCheck;
  grpcReady: ComponentCheck;
  database: ComponentCheck;
  migrations: ComponentCheck;
  signingKeys: ComponentCheck;
  certificateIssuer: ComponentCheck;
  dbPool: {
    maxConnections: number;
    minConnections: number;
    acquireTimeoutSecs: number;
    connectTimeoutSecs: number;
    idleTimeoutSecs: number;
    maxLifetimeSecs: number;
    size: number;
    idle: number;
  };
  signingKeyState: {
    configuredKeyId: string;
    encryptedCount: number;
    plaintextCount: number;
    totalCount: number;
    plaintextAllowed: boolean;
  } | null;
  auditRetention: {
    enabled: boolean;
    days: number;
    cleanupIntervalSecs: number;
    cleanupBatchSize: number;
    lastCleanup: Record<string, unknown> | null;
  };
  rateLimits: {
    enabled: boolean;
    policies: Array<{
      category: string;
      maxRequests: number;
      windowSecs: number;
    }>;
  };
};

type SystemStatusResponse = {
  systemStatus: SystemStatus;
};

const SYSTEM_STATUS_QUERY = `
  query SystemStatus {
    systemStatus {
      status
      httpReady { status message }
      grpcReady { status message }
      database { status message }
      migrations { status message }
      signingKeys { status message }
      certificateIssuer { status message }
      dbPool {
        maxConnections
        minConnections
        acquireTimeoutSecs
        connectTimeoutSecs
        idleTimeoutSecs
        maxLifetimeSecs
        size
        idle
      }
      signingKeyState {
        configuredKeyId
        encryptedCount
        plaintextCount
        totalCount
        plaintextAllowed
      }
      auditRetention {
        enabled
        days
        cleanupIntervalSecs
        cleanupBatchSize
        lastCleanup
      }
      rateLimits {
        enabled
        policies { category maxRequests windowSecs }
      }
    }
  }
`;

export function SystemHealthPage() {
  const query = useQuery({
    queryKey: ["operations", "system-status"],
    queryFn: ({ signal }) =>
      graphqlClient<SystemStatusResponse>({
        query: SYSTEM_STATUS_QUERY,
        signal,
      }),
    refetchInterval: 30_000,
  });

  if (query.isLoading) {
    return <SystemHealthSkeleton />;
  }

  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle />
        <AlertTitle>System status unavailable</AlertTitle>
        <AlertDescription>{query.error.message}</AlertDescription>
      </Alert>
    );
  }

  const status = query.data?.systemStatus;
  if (!status) return null;

  const checks = [
    { label: "HTTP", icon: Activity, check: status.httpReady },
    { label: "gRPC", icon: RadioTower, check: status.grpcReady },
    { label: "Database", icon: Database, check: status.database },
    { label: "Migrations", icon: CheckCircle2, check: status.migrations },
    { label: "Signing Keys", icon: KeyRound, check: status.signingKeys },
    {
      label: "Certificate Issuer",
      icon: ShieldCheck,
      check: status.certificateIssuer,
    },
  ];
  const poolUsed = Math.max(0, status.dbPool.size - status.dbPool.idle);

  return (
    <div className="grid gap-6">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {checks.map((item) => (
          <Card key={item.label}>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2">
                  <item.icon className="size-4" />
                  {item.label}
                </span>
                <StatusPill status={item.check.status} />
              </CardDescription>
              <CardTitle className="text-base">{item.check.message}</CardTitle>
            </CardHeader>
          </Card>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Gauge className="size-4" />
              DB Pool
            </CardTitle>
            <CardDescription>
              {poolUsed} active / {status.dbPool.size} open /{" "}
              {status.dbPool.maxConnections} max
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MetricGrid
              items={[
                ["Min", status.dbPool.minConnections],
                ["Acquire timeout", `${status.dbPool.acquireTimeoutSecs}s`],
                ["Connect timeout", `${status.dbPool.connectTimeoutSecs}s`],
                ["Idle timeout", `${status.dbPool.idleTimeoutSecs}s`],
                ["Max lifetime", `${status.dbPool.maxLifetimeSecs}s`],
              ]}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="size-4" />
              Signing Key Storage
            </CardTitle>
            <CardDescription>
              {status.signingKeyState?.configuredKeyId ?? "not available"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MetricGrid
              items={[
                ["Encrypted", status.signingKeyState?.encryptedCount ?? 0],
                ["Plaintext", status.signingKeyState?.plaintextCount ?? 0],
                ["Total", status.signingKeyState?.totalCount ?? 0],
                [
                  "Plaintext fallback",
                  status.signingKeyState?.plaintextAllowed ? "enabled" : "off",
                ],
              ]}
            />
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Audit Retention</CardTitle>
            <CardDescription>
              {status.auditRetention.enabled ? "enabled" : "disabled"} ·{" "}
              {status.auditRetention.days} days
            </CardDescription>
          </CardHeader>
          <CardContent>
            <MetricGrid
              items={[
                [
                  "Cleanup interval",
                  `${status.auditRetention.cleanupIntervalSecs}s`,
                ],
                ["Batch size", status.auditRetention.cleanupBatchSize],
                [
                  "Last deleted",
                  String(
                    status.auditRetention.lastCleanup?.deleted_rows ??
                      status.auditRetention.lastCleanup?.deletedRows ??
                      0,
                  ),
                ],
              ]}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rate Limits</CardTitle>
            <CardDescription>
              {status.rateLimits.enabled ? "enabled" : "disabled"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-2">
              {status.rateLimits.policies.map((policy) => (
                <div
                  className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm"
                  key={policy.category}
                >
                  <span className="font-medium">{policy.category}</span>
                  <span className="text-muted-foreground tabular-nums">
                    {policy.maxRequests}/{policy.windowSecs}s
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function StatusPill({ status }: { status: ComponentStatus }) {
  const variant =
    status === "error"
      ? "destructive"
      : status === "degraded"
        ? "outline"
        : "secondary";
  const Icon =
    status === "error"
      ? AlertTriangle
      : status === "disabled"
        ? CircleSlash
        : CheckCircle2;
  return (
    <Badge className="gap-1" variant={variant}>
      <Icon className="size-3" />
      {status}
    </Badge>
  );
}

function MetricGrid({ items }: { items: Array<[string, string | number]> }) {
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {items.map(([label, value]) => (
        <div className="rounded-md border px-3 py-2" key={label}>
          <div className="text-xs text-muted-foreground">{label}</div>
          <div className="mt-1 font-medium tabular-nums">{value}</div>
        </div>
      ))}
    </div>
  );
}

function SystemHealthSkeleton() {
  const skeletonCards = ["http", "grpc", "db", "migrations", "keys", "certs"];

  return (
    <div className="grid gap-6">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {skeletonCards.map((card) => (
          <Card key={card}>
            <CardHeader>
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-6 w-full" />
            </CardHeader>
          </Card>
        ))}
      </section>
      <section className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <Skeleton className="h-56 w-full" />
        <Skeleton className="h-56 w-full" />
      </section>
    </div>
  );
}
