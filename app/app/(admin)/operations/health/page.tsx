import { Activity } from "lucide-react";
import type { Metadata } from "next";
import { SystemHealthPage } from "@/components/operations/system-health-page";

export const metadata: Metadata = { title: "System Health" };

export default function OperationsHealthPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <Activity className="size-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">
            System Health
          </h1>
        </div>
      </div>
      <SystemHealthPage />
    </section>
  );
}
