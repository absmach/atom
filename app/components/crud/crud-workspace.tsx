import { Database } from "lucide-react";
import { cookies } from "next/headers";

import { CrudTable } from "@/components/crud/crud-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { type CrudFilter, requireResource } from "@/lib/crud/resources";
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
  const filterResultPromise = resolveFilters(
    resource.filters,
    resourceKey,
    searchParams,
    tenantId && resource.tenantFilter ? tenantId : undefined,
  );

  let rows: Row[] = resource.sampleRows;
  let total = resource.sampleRows.length;
  let source: "graphql" | "scaffold" = "scaffold";
  let fetchError: Error | null = null;

  if (resource.listQuery) {
    const variables: Record<string, unknown> = { limit, offset };
    if (tenantId && resource.tenantFilter) variables.tenantId = tenantId;
    for (const filter of resource.filters ?? []) {
      const raw = searchParams[`${resourceKey}.${filter.key}`];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value && value !== "all") {
        variables[filter.variable ?? filter.key] = value;
      }
    }

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
  const { error: filterFetchError, filters } = await filterResultPromise;

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
      {filterFetchError ? (
        <Alert variant="destructive">
          <Database className="size-4" />
          <AlertTitle>Filter options unavailable</AlertTitle>
          <AlertDescription>{filterFetchError.message}</AlertDescription>
        </Alert>
      ) : null}

      <CrudTable
        filters={filters}
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

async function resolveFilters(
  filters: CrudFilter[] | undefined,
  resourceKey: string,
  searchParams: Record<string, string | string[] | undefined>,
  tenantId: string | undefined,
): Promise<{ filters: CrudFilter[] | undefined; error: Error | null }> {
  if (!filters?.some((filter) => filter.optionsQuery)) {
    return { filters, error: null };
  }

  let firstError: Error | null = null;
  const resolved = await Promise.all(
    filters.map(async (filter) => {
      if (!filter.optionsQuery || !filter.optionsQueryName) return filter;

      try {
        const data = await graphqlServer<Record<string, string[]>>({
          query: filter.optionsQuery,
          variables: tenantId ? { tenantId } : {},
        });
        const rawSelected = searchParams[`${resourceKey}.${filter.key}`];
        const selected = Array.isArray(rawSelected)
          ? rawSelected[0]
          : rawSelected;
        const values = new Set(
          (data[filter.optionsQueryName] ?? [])
            .map((value) => value.trim())
            .filter(Boolean),
        );
        if (selected && selected !== "all") values.add(selected);

        return {
          ...filter,
          options: Array.from(values)
            .sort((a, b) => a.localeCompare(b))
            .map((value) => ({
              label: formatFilterOption(value),
              value,
            })),
        };
      } catch (err) {
        firstError ??=
          err instanceof Error
            ? err
            : new Error("Filter options request failed");
        return filter;
      }
    }),
  );

  return { filters: resolved, error: firstError };
}

function formatFilterOption(value: string) {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
