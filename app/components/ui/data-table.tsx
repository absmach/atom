"use client";

import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  type Table as ReactTable,
  type RowData,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";

declare module "@tanstack/react-table" {
  // Lets a column opt into extra cell/header classes (e.g. a sticky actions
  // column). Consumed by the header and body cell renderers below.
  // biome-ignore lint/correctness/noUnusedVariables: augmentation must match the upstream generic signature
  interface ColumnMeta<TData extends RowData, TValue> {
    className?: string;
  }
}

import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  SlidersHorizontal,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const PAGE_SIZES = [10, 20, 50] as const;
const EMPTY_FILTERS: NonNullable<DataTableProps<unknown, unknown>["filters"]> =
  [];
const NO_SERVER_FILTERS: NonNullable<
  DataTableProps<unknown, unknown>["serverFilters"]
> = {};

export type DataTableProps<TData, TValue> = {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  total: number;
  page: number;
  limit: number;
  /**
   * Namespaces all URL params for this table instance.
   * e.g. paramKey="tenants" → tenants.page, tenants.limit, tenants.q
   */
  paramKey: string;
  searchPlaceholder?: string;
  noResultsMessage?: string;
  statusFilter?: {
    enabled: boolean;
    label?: string;
    options?: string[];
  };
  filters?: Array<{
    key: string;
    label: string;
    allLabel?: string;
    type: "text" | "select";
    placeholder?: string;
    options?: Array<{ label: string; value: string }>;
  }>;
  /**
   * Filters the backend already applied when it produced `data` and `total`,
   * so the two stay in sync and paging through the filtered set works.
   * Anything left out is filtered in the browser over the current page only —
   * see the footer row count below.
   */
  serverFilters?: { search?: boolean; status?: boolean };
  sortOptions?: Array<{ label: string; value: string }>;
  /** Rendered in the top-right toolbar area (e.g. a Create button). */
  toolbar?: React.ReactNode;
};

export function DataTable<TData, TValue>({
  columns,
  data,
  total,
  page,
  limit,
  paramKey,
  searchPlaceholder = "Search…",
  noResultsMessage = "No results.",
  statusFilter,
  filters = EMPTY_FILTERS,
  serverFilters = NO_SERVER_FILTERS,
  sortOptions = [],
  toolbar,
}: DataTableProps<TData, TValue>) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [searchValue, setSearchValue] = useState(
    () => searchParams.get(`${paramKey}.q`) ?? "",
  );
  const [statusValue, setStatusValue] = useState(
    () => searchParams.get(`${paramKey}.status`) ?? "all",
  );
  const [filterValues, setFilterValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      filters.map((filter) => [
        filter.key,
        searchParams.get(`${paramKey}.${filter.key}`) ?? "",
      ]),
    ),
  );
  const searchTimeout = useRef<ReturnType<typeof setTimeout>>(null);
  const filterTimeouts = useRef<
    Record<string, ReturnType<typeof setTimeout> | undefined>
  >({});

  // Keep local search value in sync when the URL param changes externally.
  const urlQ = searchParams.get(`${paramKey}.q`) ?? "";
  useEffect(() => {
    setSearchValue(urlQ);
  }, [urlQ]);
  const urlStatus = searchParams.get(`${paramKey}.status`) ?? "all";
  useEffect(() => {
    setStatusValue(urlStatus);
  }, [urlStatus]);
  useEffect(() => {
    const nextValues = Object.fromEntries(
      filters.map((filter) => [
        filter.key,
        searchParams.get(`${paramKey}.${filter.key}`) ?? "",
      ]),
    );
    setFilterValues((current) =>
      recordsEqual(current, nextValues) ? current : nextValues,
    );
  }, [filters, paramKey, searchParams]);

  function buildUrl(updates: Record<string, string | null>) {
    const params = new URLSearchParams(searchParams.toString());
    for (const [key, value] of Object.entries(updates)) {
      if (value === null || value === "") params.delete(key);
      else params.set(key, value);
    }
    const qs = params.toString();
    return `${pathname}${qs ? `?${qs}` : ""}`;
  }

  function handleSearchChange(value: string) {
    setSearchValue(value);
    if (searchTimeout.current) clearTimeout(searchTimeout.current);
    searchTimeout.current = setTimeout(() => {
      router.replace(
        buildUrl({
          [`${paramKey}.q`]: value || null,
          [`${paramKey}.page`]: null,
        }),
      );
    }, 400);
  }

  function handleStatusChange(value: string) {
    setStatusValue(value);
    router.replace(
      buildUrl({
        [`${paramKey}.status`]: value === "all" ? null : value,
        [`${paramKey}.page`]: null,
      }),
    );
  }

  // Combined status + lifecycle control: a single dropdown that selects a
  // status (Live + active/disabled) or "deleted", driving both URL params.
  function handleLifecycleStatusChange(value: string) {
    const deleted = value === "deleted";
    setStatusValue(deleted ? "all" : value);
    setFilterValues((current) => ({
      ...current,
      deleted: deleted ? "deleted" : "",
    }));
    router.replace(
      buildUrl({
        [`${paramKey}.status`]: deleted || value === "all" ? null : value,
        [`${paramKey}.deleted`]: deleted ? "deleted" : null,
        [`${paramKey}.page`]: null,
      }),
    );
  }

  function commitFilterChange(key: string, value: string) {
    router.replace(
      buildUrl({
        [`${paramKey}.${key}`]: value === "all" ? null : value || null,
        [`${paramKey}.page`]: null,
      }),
    );
  }

  function handleFilterChange(
    filter: NonNullable<DataTableProps<TData, TValue>["filters"]>[number],
    value: string,
  ) {
    setFilterValues((current) => ({ ...current, [filter.key]: value }));
    if (filter.type === "text") {
      const existing = filterTimeouts.current[filter.key];
      if (existing) clearTimeout(existing);
      filterTimeouts.current[filter.key] = setTimeout(() => {
        commitFilterChange(filter.key, value);
      }, 400);
      return;
    }
    commitFilterChange(filter.key, value);
  }

  function handleSortOrderChange(value: string) {
    router.replace(
      buildUrl({
        [`${paramKey}.order`]: value,
        [`${paramKey}.dir`]: defaultSortDir(value),
        [`${paramKey}.page`]: null,
      }),
    );
  }

  function handleSortDirChange(value: string) {
    router.replace(
      buildUrl({
        [`${paramKey}.dir`]: value,
        [`${paramKey}.page`]: null,
      }),
    );
  }

  const statusOptions = React.useMemo(() => {
    if (!statusFilter?.enabled) return [];
    const configured = (statusFilter.options ?? [])
      .map((option) => option.trim())
      .filter(Boolean);
    const values = new Set(configured);
    // Only fall back to row-derived statuses when none are configured; deriving
    // from the current page would make the options shift as filters change.
    if (configured.length === 0) {
      for (const row of data) {
        const status = (row as Record<string, unknown>).status;
        if (typeof status === "string" && status.trim().length > 0) {
          values.add(status);
        }
      }
    }
    if (statusValue !== "all") values.add(statusValue);
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [data, statusFilter, statusValue]);

  // The lifecycle (live/deleted) filter is merged into the status dropdown, so
  // pull it out of the generic filter row and render the rest separately.
  const lifecycleFilter = filters.find((filter) => filter.key === "deleted");
  const restFilters = filters.filter((filter) => filter.key !== "deleted");
  const lifecycleStatusValue =
    filterValues.deleted === "deleted" ? "deleted" : statusValue;
  const sortOrder = sortOptions.some(
    (option) => option.value === searchParams.get(`${paramKey}.order`),
  )
    ? (searchParams.get(`${paramKey}.order`) ?? "created_at")
    : "created_at";
  const rawSortDir = searchParams.get(`${paramKey}.dir`);
  const sortDir =
    rawSortDir === "asc" || rawSortDir === "desc"
      ? rawSortDir
      : defaultSortDir(sortOrder);

  // Filters the backend applied already narrowed `data` and `total` together,
  // so re-applying them here would be redundant. What is left runs client-side
  // over the current page only, because the backend has no text search for this
  // resource.
  const clientSearch = serverFilters.search ? "" : searchValue;
  const clientStatus = serverFilters.status ? "all" : statusValue;
  const isClientFiltered = clientSearch !== "" || clientStatus !== "all";

  const filteredData = isClientFiltered
    ? data.filter((row) => {
        const matchesSearch =
          !clientSearch ||
          JSON.stringify(row)
            .toLowerCase()
            .includes(clientSearch.toLowerCase());
        const matchesStatus =
          clientStatus === "all" ||
          String((row as Record<string, unknown>).status ?? "") ===
            clientStatus;
        return matchesSearch && matchesStatus;
      })
    : data;

  // `total` counts the whole server-side result set, which is only what the
  // user sees while every active filter was applied server-side. Once we narrow
  // rows in the browser the reachable set is just this page, so report that
  // instead of leaving a stale unfiltered count in the footer.
  const rowCount = isClientFiltered ? filteredData.length : total;
  const pageCount = isClientFiltered
    ? 1
    : total > 0
      ? Math.ceil(total / limit)
      : 1;
  const currentPage = Math.min(page, pageCount);

  const table = useReactTable({
    data: filteredData,
    columns,
    rowCount,
    manualPagination: true,
    getCoreRowModel: getCoreRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    state: {
      columnVisibility,
      pagination: { pageIndex: currentPage - 1, pageSize: limit },
    },
  });

  const colCount = table.getVisibleLeafColumns().length;

  return (
    <div className="grid gap-4">
      {/* Toolbar row */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label={searchPlaceholder}
              className="h-9 w-full pl-9 sm:w-72"
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder={searchPlaceholder}
              value={searchValue}
            />
          </div>
          {statusFilter?.enabled || lifecycleFilter ? (
            <LifecycleStatusFilter
              hasLifecycle={Boolean(lifecycleFilter)}
              label={statusFilter?.label ?? "Status"}
              onChange={
                lifecycleFilter
                  ? handleLifecycleStatusChange
                  : handleStatusChange
              }
              options={statusOptions}
              value={lifecycleStatusValue}
            />
          ) : null}
          {restFilters.map((filter) =>
            filter.type === "select" ? (
              <SelectFilter
                filter={filter}
                key={filter.key}
                onChange={(value) => handleFilterChange(filter, value)}
                value={filterValues[filter.key] || "all"}
              />
            ) : (
              <div className="relative" key={filter.key}>
                <Input
                  aria-label={`Filter by ${filter.label}`}
                  className="h-9 w-full sm:w-48"
                  onChange={(event) =>
                    handleFilterChange(filter, event.target.value)
                  }
                  placeholder={filter.placeholder ?? filter.label}
                  value={filterValues[filter.key] ?? ""}
                />
              </div>
            ),
          )}
          {sortOptions.length > 0 ? (
            <SortControl
              dir={sortDir}
              onDirChange={handleSortDirChange}
              onOrderChange={handleSortOrderChange}
              options={sortOptions}
              order={sortOrder}
            />
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <DataTableViewOptions table={table} />
          {toolbar}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-md border bg-card">
        {/* min-w-max lets the table grow to its natural width so wide rows
            scroll horizontally instead of compressing columns under the pinned
            actions column. */}
        <Table className="min-w-max">
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => (
                  <TableHead
                    key={h.id}
                    className={
                      (
                        h.column.columnDef.meta as
                          | { className?: string }
                          | undefined
                      )?.className
                    }
                  >
                    {h.isPlaceholder
                      ? null
                      : flexRender(h.column.columnDef.header, h.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length > 0 ? (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell
                      key={cell.id}
                      className={
                        (
                          cell.column.columnDef.meta as
                            | { className?: string }
                            | undefined
                        )?.className
                      }
                    >
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  className="h-24 text-center text-sm text-muted-foreground"
                  colSpan={colCount}
                >
                  {noResultsMessage}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination footer */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-sm text-muted-foreground">
          {rowCount} row{rowCount !== 1 ? "s" : ""}
        </span>
        <div className="flex items-center gap-4">
          <div className="hidden items-center gap-2 sm:flex">
            <span className="text-sm text-muted-foreground">Rows per page</span>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm" variant="outline">
                  {limit}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {PAGE_SIZES.map((size) => (
                  <Link
                    href={buildUrl({
                      [`${paramKey}.limit`]: String(size),
                      [`${paramKey}.page`]: null,
                    })}
                    key={size}
                    scroll={false}
                  >
                    <DropdownMenuCheckboxItem checked={limit === size}>
                      {size}
                    </DropdownMenuCheckboxItem>
                  </Link>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          <span className="w-28 text-center text-sm text-muted-foreground">
            Page {pageCount > 0 ? currentPage : 0} of {pageCount}
          </span>

          <div className="flex items-center gap-1">
            <PageLink
              aria-label="First page"
              disabled={currentPage <= 1}
              href={buildUrl({ [`${paramKey}.page`]: "1" })}
            >
              <ChevronsLeft className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Previous page"
              disabled={currentPage <= 1}
              href={buildUrl({ [`${paramKey}.page`]: String(currentPage - 1) })}
            >
              <ChevronLeft className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Next page"
              disabled={currentPage >= pageCount}
              href={buildUrl({ [`${paramKey}.page`]: String(currentPage + 1) })}
            >
              <ChevronRight className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Last page"
              disabled={currentPage >= pageCount}
              href={buildUrl({ [`${paramKey}.page`]: String(pageCount) })}
            >
              <ChevronsRight className="size-4" />
            </PageLink>
          </div>
        </div>
      </div>
    </div>
  );
}

function recordsEqual(
  left: Record<string, string>,
  right: Record<string, string>,
) {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every((key) => left[key] === right[key])
  );
}

function defaultSortDir(order: string) {
  return order === "created_at" || order === "updated_at" ? "desc" : "asc";
}

function SortControl({
  dir,
  onDirChange,
  onOrderChange,
  options,
  order,
}: {
  dir: string;
  onDirChange: (value: string) => void;
  onOrderChange: (value: string) => void;
  options: Array<{ label: string; value: string }>;
  order: string;
}) {
  const orderLabelId = React.useId();
  const dirLabelId = React.useId();

  return (
    <div className="flex min-w-0 gap-2">
      <FilterField label="Sort" labelId={orderLabelId}>
        <Select onValueChange={onOrderChange} value={order}>
          <SelectTrigger
            aria-labelledby={orderLabelId}
            className="h-9 w-full sm:w-40"
          >
            <SelectValue placeholder="Sort" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {options.map((option) => (
                <SelectItem key={option.value} value={option.value}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </FilterField>
      <FilterField label="Direction" labelId={dirLabelId}>
        <Select onValueChange={onDirChange} value={dir}>
          <SelectTrigger
            aria-labelledby={dirLabelId}
            className="h-9 w-full sm:w-28"
          >
            <SelectValue placeholder="Direction" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="asc">Asc</SelectItem>
              <SelectItem value="desc">Desc</SelectItem>
            </SelectGroup>
          </SelectContent>
        </Select>
      </FilterField>
    </div>
  );
}

function DataTableViewOptions<TData>({ table }: { table: ReactTable<TData> }) {
  const hideable = table
    .getAllColumns()
    .filter(
      (column) =>
        typeof column.accessorFn !== "undefined" && column.getCanHide(),
    );

  if (hideable.length === 0) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          className="flex hover:bg-primary/10"
          size="sm"
          variant="outline"
        >
          <SlidersHorizontal className="mr-2 size-4" />
          View
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-37.5">
        <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {hideable.map((column) => (
          <DropdownMenuCheckboxItem
            checked={column.getIsVisible()}
            className="capitalize hover:bg-primary/10 focus:bg-primary/10"
            key={column.id}
            onCheckedChange={(value) => column.toggleVisibility(!!value)}
          >
            {column.id}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function LifecycleStatusFilter({
  hasLifecycle,
  label,
  onChange,
  options,
  value,
}: {
  hasLifecycle: boolean;
  label: string;
  onChange: (value: string) => void;
  options: string[];
  value: string;
}) {
  const labelId = React.useId();

  return (
    <FilterField label={label} labelId={labelId}>
      <Select onValueChange={onChange} value={value}>
        <SelectTrigger aria-labelledby={labelId} className="h-9 w-full sm:w-44">
          <SelectValue placeholder={label} />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="all">{hasLifecycle ? "Live" : "All"}</SelectItem>
            {options.map((option) => (
              <SelectItem key={option} value={option}>
                {capitalize(option)}
              </SelectItem>
            ))}
            {hasLifecycle ? (
              <SelectItem value="deleted">Deleted</SelectItem>
            ) : null}
          </SelectGroup>
        </SelectContent>
      </Select>
    </FilterField>
  );
}

function SelectFilter({
  filter,
  onChange,
  value,
}: {
  filter: {
    key: string;
    label: string;
    allLabel?: string;
    options?: Array<{ label: string; value: string }>;
  };
  onChange: (value: string) => void;
  value: string;
}) {
  const labelId = React.useId();

  return (
    <FilterField label={filter.label} labelId={labelId}>
      <Select onValueChange={onChange} value={value || "all"}>
        <SelectTrigger aria-labelledby={labelId} className="h-9 w-full sm:w-44">
          <SelectValue placeholder={filter.label} />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="all">
              {filter.allLabel ?? `All ${filter.label}`}
            </SelectItem>
            {(filter.options ?? []).map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </FilterField>
  );
}

function FilterField({
  children,
  label,
  labelId,
}: {
  children: React.ReactNode;
  label: string;
  labelId: string;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span
        className="px-1 text-xs font-medium leading-none text-muted-foreground"
        id={labelId}
      >
        {label}
      </span>
      {children}
    </div>
  );
}

function capitalize(value: string) {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function PageLink({
  children,
  disabled,
  href,
  "aria-label": ariaLabel,
}: {
  children: React.ReactNode;
  disabled: boolean;
  href: string;
  "aria-label": string;
}) {
  const base =
    "flex size-8 items-center justify-center rounded-md border text-sm transition-colors";
  if (disabled) {
    return (
      <span
        className={`${base} pointer-events-none bg-muted text-muted-foreground`}
      >
        <span className="sr-only">{ariaLabel}</span>
        {children}
      </span>
    );
  }
  return (
    <Link
      aria-label={ariaLabel}
      className={`${base} bg-primary text-primary-foreground hover:bg-primary/90`}
      href={href}
      scroll={false}
    >
      {children}
    </Link>
  );
}
