"use client";

import { useQuery } from "@tanstack/react-query";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  type Table as ReactTable,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  Search,
  SlidersHorizontal,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { AuditExportDialog } from "@/components/audit/audit-export-dialog";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import { DateTimePicker } from "@/components/ui/date-time-picker";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { JsonEditor } from "@/components/ui/json-editor";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { graphqlClient } from "@/lib/graphql/client";
import { tenantQueryValue } from "@/lib/tenant/context";

const AUDIT_INSPECT_ENTITY_QUERY = `query AuditInspectEntity($id: ID!) { entity(id: $id) { id name kind } }`;
const AUDIT_INSPECT_TENANT_QUERY = `query AuditInspectTenant($id: ID!) { tenant(id: $id) { id name } }`;

// ─── GraphQL ──────────────────────────────────────────────────────────────────

const AUDIT_LOGS_QUERY = `
  query AuditLogs(
    $limit: Int
    $offset: Int
    $event: String
    $outcome: AuditOutcome
    $from: String
    $to: String
    $tenantId: ID
  ) {
    auditLogs(
      limit: $limit
      offset: $offset
      event: $event
      outcome: $outcome
      from: $from
      to: $to
      tenantId: $tenantId
    ) {
      total
      items {
        id
        event
        outcome
        entityId
        tenantId
        details
        createdAt
      }
    }
  }
`;

// ─── Types / constants ────────────────────────────────────────────────────────

const PAGE_SIZES = [10, 20, 50] as const;
const DEFAULT_PAGE_SIZE = 20;
const NONE = "__none__";

type AuditLogItem = {
  id: string;
  event: string;
  outcome: string;
  entityId: string | null;
  tenantId: string | null;
  details: Record<string, unknown>;
  createdAt: string;
};

type AuditLogsResponse = {
  auditLogs: { total: number; items: AuditLogItem[] };
};

// ─── URL param hook ───────────────────────────────────────────────────────────

function useAuditParams() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const page = Math.max(1, Number(searchParams.get("audit.page") ?? "1") || 1);
  const rawLimit = Number(
    searchParams.get("audit.limit") ?? String(DEFAULT_PAGE_SIZE),
  );
  const limit = (PAGE_SIZES as readonly number[]).includes(rawLimit)
    ? rawLimit
    : DEFAULT_PAGE_SIZE;
  const event = searchParams.get("audit.event") ?? "";
  const outcome = searchParams.get("audit.outcome") ?? "";
  const from = searchParams.get("audit.from") ?? "";
  const to = searchParams.get("audit.to") ?? "";

  function buildUrl(updates: Record<string, string | null>) {
    const params = new URLSearchParams(searchParams.toString());
    for (const [key, value] of Object.entries(updates)) {
      if (value === null || value === "") params.delete(key);
      else params.set(key, value);
    }
    const qs = params.toString();
    return `${pathname}${qs ? `?${qs}` : ""}`;
  }

  function setParams(updates: Record<string, string | null>, resetPage = true) {
    const merged = resetPage ? { ...updates, "audit.page": null } : updates;
    router.push(buildUrl(merged));
  }

  function clearFilters() {
    router.push(pathname);
  }

  return {
    page,
    limit,
    event,
    outcome,
    from,
    to,
    buildUrl,
    setParams,
    clearFilters,
  };
}

// ─── Page component ───────────────────────────────────────────────────────────

export function AuditLogPage() {
  const params = useAuditParams();
  const { selection } = useTenant();
  const [inspected, setInspected] = React.useState<AuditLogItem | null>(null);

  const columns = React.useMemo<ColumnDef<AuditLogItem>[]>(
    () => [
      {
        accessorKey: "createdAt",
        header: "Time",
        cell: ({ getValue }) => <DisplayTimeCell time={String(getValue())} />,
      },
      {
        accessorKey: "event",
        header: "Event",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs">{String(getValue())}</span>
        ),
      },
      {
        accessorKey: "outcome",
        header: "Outcome",
        cell: ({ getValue }) => <StatusBadge value={getValue()} />,
      },
      {
        accessorKey: "entityId",
        header: "Entity",
        cell: ({ getValue }) => {
          const v = getValue() as string | null;
          return v ? (
            <span className="font-mono text-xs text-muted-foreground">
              {v.slice(0, 8)}…
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          );
        },
      },
      {
        accessorKey: "tenantId",
        header: "Tenant",
        cell: ({ getValue }) => {
          const v = getValue() as string | null;
          return v ? (
            <span className="font-mono text-xs text-muted-foreground">
              {v.slice(0, 8)}…
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          );
        },
      },
      {
        id: "actions",
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setInspected(row.original)}
            >
              Inspect
            </Button>
          </div>
        ),
      },
    ],
    [],
  );

  const variables = React.useMemo(
    () => ({
      limit: params.limit,
      offset: (params.page - 1) * params.limit,
      event: params.event || undefined,
      outcome: params.outcome || undefined,
      from: params.from || undefined,
      to: params.to || undefined,
      tenantId: tenantQueryValue(selection) ?? undefined,
    }),
    [
      params.page,
      params.limit,
      params.event,
      params.outcome,
      params.from,
      params.to,
      selection,
    ],
  );

  const { data } = useQuery({
    queryKey: ["audit-logs", variables],
    queryFn: ({ signal }) =>
      graphqlClient<AuditLogsResponse>({
        query: AUDIT_LOGS_QUERY,
        variables,
        signal,
      }),
    staleTime: 15_000,
    placeholderData: (prev) => prev,
  });

  const items = data?.auditLogs.items ?? [];
  const total = data?.auditLogs.total ?? 0;

  return (
    <>
      <AuditTable
        columns={columns}
        data={items}
        total={total}
        params={params}
        toolbar={
          <AuditExportDialog
            defaultEvent={params.event}
            defaultOutcome={params.outcome}
            defaultFrom={params.from}
            defaultTo={params.to}
          />
        }
      />

      {/* ── Inspect sheet ── */}
      <Sheet
        open={Boolean(inspected)}
        onOpenChange={(o) => !o && setInspected(null)}
      >
        <SheetContent className="w-full overflow-y-auto sm:w-[min(90vw,48rem)]! sm:max-w-lg!">
          <SheetHeader>
            <SheetTitle>Audit log entry</SheetTitle>
          </SheetHeader>
          {inspected ? <AuditInspect item={inspected} /> : null}
        </SheetContent>
      </Sheet>
    </>
  );
}

// ─── AuditTable ───────────────────────────────────────────────────────────────

type AuditTableParams = ReturnType<typeof useAuditParams>;

function AuditTable({
  columns,
  data,
  total,
  params,
  toolbar,
}: {
  columns: ColumnDef<AuditLogItem>[];
  data: AuditLogItem[];
  total: number;
  params: AuditTableParams;
  toolbar?: React.ReactNode;
}) {
  const {
    page,
    limit,
    event,
    outcome,
    from,
    to,
    buildUrl,
    setParams,
    clearFilters,
  } = params;

  const [columnVisibility, setColumnVisibility] =
    React.useState<VisibilityState>({});

  // Debounced event search
  const searchTimeout = React.useRef<ReturnType<typeof setTimeout>>(null);
  const [searchValue, setSearchValue] = React.useState(event);
  React.useEffect(() => {
    setSearchValue(event);
  }, [event]);

  function handleSearchChange(value: string) {
    setSearchValue(value);
    if (searchTimeout.current) clearTimeout(searchTimeout.current);
    searchTimeout.current = setTimeout(() => {
      setParams({ "audit.event": value || null });
    }, 400);
  }

  const table = useReactTable({
    data,
    columns,
    rowCount: total,
    manualPagination: true,
    getCoreRowModel: getCoreRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    state: {
      columnVisibility,
      pagination: { pageIndex: page - 1, pageSize: limit },
    },
  });

  const pageCount = total > 0 ? Math.ceil(total / limit) : 1;
  const colCount = table.getVisibleLeafColumns().length;
  const hasFilters = Boolean(event || outcome || from || to);

  return (
    <div className="grid gap-4">
      {/* Toolbar row */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          {/* Event search */}
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">Event</Label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="h-9 w-full pl-9 sm:w-56"
                placeholder="Filter by event…"
                value={searchValue}
                onChange={(e) => handleSearchChange(e.target.value)}
              />
            </div>
          </div>

          {/* Outcome filter */}
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">Outcome</Label>
            <Select
              value={outcome || NONE}
              onValueChange={(v) =>
                setParams({ "audit.outcome": v === NONE ? null : v })
              }
            >
              <SelectTrigger className="h-9 w-full sm:w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NONE}>All outcomes</SelectItem>
                <SelectItem value="allow">Allow</SelectItem>
                <SelectItem value="deny">Deny</SelectItem>
                <SelectItem value="error">Error</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Date range */}
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">From</Label>
            <DateTimePicker
              value={from || undefined}
              onChange={(v) => setParams({ "audit.from": v || null })}
              placeholder="From"
              className="h-9 w-52"
            />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">To</Label>
            <DateTimePicker
              value={to || undefined}
              onChange={(v) => setParams({ "audit.to": v || null })}
              placeholder="To"
              className="h-9 w-52"
            />
          </div>

          {hasFilters ? (
            <Button
              variant="ghost"
              size="sm"
              className="h-9 self-end text-xs"
              onClick={clearFilters}
            >
              Clear
            </Button>
          ) : null}
        </div>

        {/* Right side: view + toolbar */}
        <div className="flex items-center gap-2 self-end">
          <ViewOptions table={table} />
          {toolbar}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-md border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => (
                  <TableHead key={h.id}>
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
                    <TableCell key={cell.id}>
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
                  No audit logs found.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination footer */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? "row" : "rows"}
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
                    key={size}
                    href={buildUrl({
                      "audit.limit": String(size),
                      "audit.page": null,
                    })}
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
            Page {pageCount > 0 ? page : 0} of {pageCount}
          </span>

          <div className="flex items-center gap-1">
            <PageLink
              aria-label="First page"
              disabled={page <= 1}
              href={buildUrl({ "audit.page": "1" })}
            >
              <ChevronsLeft className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Previous page"
              disabled={page <= 1}
              href={buildUrl({ "audit.page": String(page - 1) })}
            >
              <ChevronLeft className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Next page"
              disabled={page >= pageCount}
              href={buildUrl({ "audit.page": String(page + 1) })}
            >
              <ChevronRight className="size-4" />
            </PageLink>
            <PageLink
              aria-label="Last page"
              disabled={page >= pageCount}
              href={buildUrl({ "audit.page": String(pageCount) })}
            >
              <ChevronsRight className="size-4" />
            </PageLink>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── View options (column visibility) ────────────────────────────────────────

function ViewOptions<TData>({ table }: { table: ReactTable<TData> }) {
  const hideable = table
    .getAllColumns()
    .filter((c) => typeof c.accessorFn !== "undefined" && c.getCanHide());

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
        {hideable.map((col) => (
          <DropdownMenuCheckboxItem
            key={col.id}
            checked={col.getIsVisible()}
            className="capitalize hover:bg-primary/10 focus:bg-primary/10"
            onCheckedChange={(v) => col.toggleVisibility(!!v)}
          >
            {col.id}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ─── PageLink (mirrors DataTable) ─────────────────────────────────────────────

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

// ─── Inspect panel ────────────────────────────────────────────────────────────

function AuditInspect({ item }: { item: AuditLogItem }) {
  const [copied, setCopied] = React.useState(false);

  const entityQ = useQuery({
    enabled: Boolean(item.entityId),
    queryKey: ["audit-inspect-entity", item.entityId],
    queryFn: ({ signal }) =>
      graphqlClient<{ entity: { id: string; name: string; kind: string } }>({
        query: AUDIT_INSPECT_ENTITY_QUERY,
        variables: { id: item.entityId },
        signal,
      }),
    staleTime: 60_000,
  });
  const tenantQ = useQuery({
    enabled: Boolean(item.tenantId),
    queryKey: ["audit-inspect-tenant", item.tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenant: { id: string; name: string } }>({
        query: AUDIT_INSPECT_TENANT_QUERY,
        variables: { id: item.tenantId },
        signal,
      }),
    staleTime: 60_000,
  });

  const entityName = entityQ.data?.entity
    ? `${entityQ.data.entity.name} (${entityQ.data.entity.kind})`
    : (item.entityId ?? null);
  const tenantName = tenantQ.data?.tenant.name ?? item.tenantId;

  function copyId() {
    navigator.clipboard.writeText(item.id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="grid gap-3 px-4 pb-6">
      <Field label="ID">
        <div className="flex items-center gap-2">
          <span className="break-all font-mono text-xs">{item.id}</span>
          <Button
            className="h-6 w-6 shrink-0"
            onClick={copyId}
            size="icon"
            variant="ghost"
          >
            {copied ? (
              <Check className="size-3.5" />
            ) : (
              <Copy className="size-3.5" />
            )}
          </Button>
        </div>
      </Field>

      <Field label="Event">
        <span className="font-mono text-xs">{item.event}</span>
      </Field>

      <Field label="Outcome">
        <StatusBadge value={item.outcome} />
      </Field>

      <Field label="Entity">
        {entityName ? (
          <span className="text-sm">{entityName}</span>
        ) : (
          <span className="text-sm text-muted-foreground">—</span>
        )}
      </Field>

      <Field label="Tenant">
        {item.tenantId ? (
          <span className="text-sm">{tenantName}</span>
        ) : (
          <span className="text-sm text-muted-foreground">—</span>
        )}
      </Field>

      <Field label="Time">
        <DisplayTimeCell time={item.createdAt} />
      </Field>

      <Field label="Details">
        <JsonEditor
          value={JSON.stringify(item.details, null, 2)}
          className="[&_.cm-editor]:min-h-16"
        />
      </Field>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 rounded-lg border bg-background p-3">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}
