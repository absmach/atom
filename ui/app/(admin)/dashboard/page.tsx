import { Activity, ShieldCheck, Users } from "lucide-react";
import type { Metadata } from "next";
import { DashboardOverview } from "@/components/dashboard/dashboard-overview";
import { RelationshipPanel } from "@/components/relationships/relationship-panel";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const metadata: Metadata = { title: "Dashboard" };

const stats = [
  { label: "Tenant boundary", value: "Global + tenant", icon: ShieldCheck },
  { label: "Access model", value: "Roles + assignments", icon: Users },
  { label: "Audit mode", value: "Query-backed", icon: Activity },
  { label: "Operations", value: "Health + keys", icon: ShieldCheck },
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
          Operate Atom identity, roles, assignments, tenant boundaries, and
          authorization explainability from task-driven workflows.
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
              Designed for operational clarity across global and tenant-owned
              objects.
            </CardContent>
          </Card>
        ))}
      </section>
      <DashboardOverview />
      <RelationshipPanel />
    </div>
  );
}
