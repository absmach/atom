import type { Metadata } from "next";
import { AuthzDebugger } from "@/components/authz-debugger";
import { parseAuthzDebuggerInitialValues } from "@/lib/authz/debugger-links";

export const metadata: Metadata = { title: "Authorization" };

export default async function AuthzPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const initialValues = parseAuthzDebuggerInitialValues(await searchParams);

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
      <AuthzDebugger initialValues={initialValues} />
    </div>
  );
}
