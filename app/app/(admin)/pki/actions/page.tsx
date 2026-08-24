import type { Metadata } from "next";
import { PkiActionsPanel } from "@/components/pki/pki-actions-panel";

export const metadata: Metadata = { title: "PKI Actions" };

export default function PkiActionsPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">PKI Actions</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Provision authorities, issue certificates from CSRs, revoke, and
          retire. Every form here fires the same GraphQL mutations the
          Playground exposes — the backend enforces platform vs tenant scope, so
          a form the caller cannot execute will surface a Forbidden error.
        </p>
      </div>
      <PkiActionsPanel />
    </section>
  );
}
