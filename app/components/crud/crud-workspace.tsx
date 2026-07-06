import { Database, ShieldX } from "lucide-react";
import { cookies } from "next/headers";

import { CrudTable } from "@/components/crud/crud-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { type CrudFilter, requireResource } from "@/lib/crud/resources";
import { isForbiddenError } from "@/lib/graphql/client";
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
  const scopedTenantId =
    tenantId && resource.tenantFilter ? tenantId : undefined;
  const filtersForPage = scopedTenantId
    ? resource.filters?.filter((filter) => filter.variable !== "tenantId")
    : resource.filters;
  const rawTenantFilter = searchParams[`${resourceKey}.tenantId`];
  const tenantFilterValue = Array.isArray(rawTenantFilter)
    ? rawTenantFilter[0]
    : rawTenantFilter;
  const selectedTenantId =
    !scopedTenantId &&
    resource.tenantFilter &&
    tenantFilterValue &&
    tenantFilterValue !== "all"
      ? tenantFilterValue
      : undefined;
  const filterResultPromise = resolveFilters(
    filtersForPage,
    resourceKey,
    searchParams,
    scopedTenantId ?? selectedTenantId,
  );

  let rows: Row[] = resource.sampleRows;
  let total = resource.sampleRows.length;
  let source: "graphql" | "scaffold" = "scaffold";
  let fetchError: Error | null = null;
  let accessDenied = false;

  if (resource.listQuery) {
    const variables: Record<string, unknown> = { limit, offset };
    if (scopedTenantId) variables.tenantId = scopedTenantId;
    for (const filter of filtersForPage ?? []) {
      const raw = searchParams[`${resourceKey}.${filter.key}`];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value && value !== "all") {
        variables[filter.variable ?? filter.key] = value;
      }
    }
    // Status lives in its own URL param (merged into the lifecycle dropdown),
    // not in `resource.filters`. Forward it server-side so the filter spans the
    // whole result set rather than just the current page. Enum values are
    // snake_case, matching the GraphQL EntityStatus values.
    const statusRaw = searchParams[`${resourceKey}.status`];
    const statusValue = Array.isArray(statusRaw) ? statusRaw[0] : statusRaw;
    if (
      statusValue &&
      statusValue !== "all" &&
      resource.listQuery.includes("$status")
    ) {
      variables.status = statusValue;
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
      accessDenied = isForbiddenError(err);
      rows = accessDenied ? [] : resource.sampleRows;
      total = accessDenied ? 0 : resource.sampleRows.length;
    }
  }
  const { error: filterFetchError, filters } = await filterResultPromise;

  // The tombstone columns (deletedAt/deletedBy) only carry data in the deleted
  // view, so hide them in the default live/active view.
  const deletedParam = searchParams[`${resourceKey}.deleted`];
  const showDeletedColumns =
    (Array.isArray(deletedParam) ? deletedParam[0] : deletedParam) ===
    "deleted";

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

      {accessDenied ? (
        <Alert variant="destructive">
          <ShieldX className="size-4" />
          <AlertTitle>Access denied</AlertTitle>
          <AlertDescription>
            This session does not have permission to read {resource.title}.
          </AlertDescription>
        </Alert>
      ) : fetchError ? (
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

      {accessDenied ? null : (
        <CrudTable
          filters={filters}
          limit={limit}
          page={page}
          resourceKey={resourceKey}
          rows={rows}
          showDeletedColumns={showDeletedColumns}
          source={source}
          total={total}
        />
      )}
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
        const data = await graphqlServer<Record<string, unknown>>({
          query: filter.optionsQuery,
          variables:
            tenantId && filter.scopeOptionsByTenant ? { tenantId } : {},
        });
        const rawSelected = searchParams[`${resourceKey}.${filter.key}`];
        const selected = Array.isArray(rawSelected)
          ? rawSelected[0]
          : rawSelected;

        return {
          ...filter,
          options: filterOptionsFromPayload(
            data[filter.optionsQueryName],
            filter,
            selected,
          ),
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

function filterOptionsFromPayload(
  payload: unknown,
  filter: CrudFilter,
  selected: string | undefined,
) {
  const rawOptions = Array.isArray(payload)
    ? payload
    : isRecord(payload) && Array.isArray(payload.items)
      ? payload.items
      : [];
  const optionsByValue = rawOptions
    .map((option) => filterOptionFromRaw(option, filter))
    .filter((option): option is { label: string; value: string } =>
      Boolean(option),
    )
    .reduce(
      (options, option) => options.set(option.value, option),
      new Map<string, { label: string; value: string }>(),
    );

  if (selected && selected !== "all" && !optionsByValue.has(selected)) {
    optionsByValue.set(selected, {
      label: filter.optionValueKey ? selected : formatFilterOption(selected),
      value: selected,
    });
  }

  return Array.from(optionsByValue.values()).sort((left, right) =>
    left.label.localeCompare(right.label),
  );
}

function filterOptionFromRaw(option: unknown, filter: CrudFilter) {
  if (typeof option === "string") {
    const value = option.trim();
    return value ? { label: formatFilterOption(value), value } : null;
  }
  if (!isRecord(option)) return null;

  const rawValue = option[filter.optionValueKey ?? "value"];
  const value = typeof rawValue === "string" ? rawValue.trim() : "";
  if (!value) return null;

  const rawLabel =
    option[filter.optionLabelKey ?? "label"] ?? option.name ?? option.label;
  const label = typeof rawLabel === "string" ? rawLabel.trim() : "";
  return { label: label || value, value };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
