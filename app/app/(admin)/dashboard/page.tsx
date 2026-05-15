import { Activity, AlertTriangle, GitBranch, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Dashboard" };

import { RelationshipPanel } from "@/components/relationships/relationship-panel";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const stats = [
  { label: "Tenant scope", value: "Global + tenant", icon: ShieldCheck },
  { label: "Policy posture", value: "DENY precedence", icon: GitBranch },
  { label: "Audit mode", value: "Query-backed", icon: Activity },
  { label: "Realtime", value: "Backend todo", icon: AlertTriangle },
];

export default function DashboardPage() {
  return (
    <div className="grid gap-6">
      <section className="grid gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            Control plane overview
          </h1>
        </div>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Operate Atom identity, RBAC, ABAC, tenant scope, and authorization
          explainability from task-driven workflows.
        </p>
      </section>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.label}>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center gap-2">
                <stat.icon className="size-4" />
                {stat.label}
              </CardDescription>
              <CardTitle className="text-lg">{stat.value}</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Designed for operational clarity across global and tenant-scoped
              management.
            </CardContent>
          </Card>
        ))}
      </section>
      <RelationshipPanel />
    </div>
  );
}
