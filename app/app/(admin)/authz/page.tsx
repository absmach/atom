import type { Metadata } from "next";
import { AuthzDebugger } from "@/components/authz-debugger";

export const metadata: Metadata = { title: "Authorization" };

export default function AuthzPage() {
  return (
    <div className="grid gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Authorization debugger
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Visualize why an Atom authorization decision was allowed or denied.
        </p>
      </div>
      <AuthzDebugger />
    </div>
  );
}
