import { AlertCircle, Database } from "lucide-react";
import { cookies } from "next/headers";

import { CrudTable } from "@/components/crud/crud-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { requireResource } from "@/lib/crud/resources";
import { graphqlServer } from "@/lib/graphql/server";
import { GLOBAL_TENANT, TENANT_COOKIE } from "@/lib/tenant/context";

const DEFAULT_LIMIT = 20;

type Row = Record<string, unknown>;

type Props = {
  resourceKey: string;
  searchParams: Record<string, string | string[] | undefined>;
};

export async function CrudWorkspace({ resourceKey, searchParams }: Props) {
  const resource = requireResource(resourceKey);

  const rawPage = searchParams[`${resourceKey}.page`];
  const rawLimit = searchParams[`${resourceKey}.limit`];
  const page = Math.max(
    1,
    Number(Array.isArray(rawPage) ? rawPage[0] : (rawPage ?? "1")) || 1,
  );
  const limit = Math.max(
    1,
    Number(
      Array.isArray(rawLimit)
        ? rawLimit[0]
        : (rawLimit ?? String(DEFAULT_LIMIT)),
    ) || DEFAULT_LIMIT,
  );
  const offset = (page - 1) * limit;

  const cookieStore = await cookies();
  const rawTenant = cookieStore.get(TENANT_COOKIE)?.value;
  const tenantId =
    rawTenant && rawTenant !== GLOBAL_TENANT ? rawTenant : undefined;

  let rows: Row[] = resource.sampleRows;
  let total = resource.sampleRows.length;
  let source: "graphql" | "scaffold" = "scaffold";
  let fetchError: Error | null = null;

  if (resource.listQuery) {
    const variables: Record<string, unknown> = { limit, offset };
    if (tenantId && resource.tenantFilter) variables.tenantId = tenantId;

    try {
      const data = await graphqlServer<
        Record<string, { items: Row[]; total: number }>
      >({
        query: resource.listQuery,
        variables,
      });
      const payload = data[resource.queryName];
      rows = payload?.items ?? [];
      total = payload?.total ?? rows.length;
      source = "graphql";
    } catch (err) {
      fetchError =
        err instanceof Error ? err : new Error("Data request failed");
      rows = resource.sampleRows;
      total = resource.sampleRows.length;
    }
  }

  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <resource.icon className="size-5 text-primary" />
          <h1 className="text-2xl font-semibold tracking-tight">
            {resource.title}
          </h1>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          {resource.description}
        </p>
      </div>

      {Object.keys(resource.missing).length ? (
        <Alert>
          <AlertCircle className="size-4" />
          <AlertTitle>Unavailable actions</AlertTitle>
          <AlertDescription>
            {Object.entries(resource.missing)
              .map(([action, reason]) => `${action}: ${reason}`)
              .join(" ")}
          </AlertDescription>
        </Alert>
      ) : null}

      {fetchError ? (
        <Alert variant="destructive">
          <Database className="size-4" />
          <AlertTitle>Backend unavailable or operation failed</AlertTitle>
          <AlertDescription>
            Showing sample data so the workflow remains inspectable.{" "}
            {fetchError.message}
          </AlertDescription>
        </Alert>
      ) : null}

      <CrudTable
        limit={limit}
        page={page}
        resourceKey={resourceKey}
        rows={rows}
        source={source}
        total={total}
      />
    </section>
  );
}
