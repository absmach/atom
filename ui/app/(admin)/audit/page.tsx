import { ScrollText } from "lucide-react";
import type { Metadata } from "next";
import { AuditLogPage } from "@/components/audit/audit-log-page";

export const metadata: Metadata = { title: "Audit Logs" };

export default function AuditPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <ScrollText className="size-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">Audit Logs</h1>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Immutable record of identity and authorization activity across the
          platform.
        </p>
      </div>
      <AuditLogPage />
    </section>
  );
}
