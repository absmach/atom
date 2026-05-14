"use client";

import { useMutation } from "@tanstack/react-query";
import { Download, Loader2 } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DateTimePicker } from "@/components/ui/date-time-picker";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { graphqlClient } from "@/lib/graphql/client";
import { tenantQueryValue } from "@/lib/tenant/context";
import { useTenant } from "@/components/app-shell/tenant-provider";

// ─── Constants ────────────────────────────────────────────────────────────────

const BATCH_SIZE = 200; // backend hard cap
const MAX_EXPORT_ROWS = 2000;
const NONE = "__none__";

export const EXPORT_COLUMNS = [
  { key: "id", label: "ID" },
  { key: "createdAt", label: "Created At" },
  { key: "event", label: "Event" },
  { key: "outcome", label: "Outcome" },
  { key: "entityId", label: "Entity ID" },
  { key: "tenantId", label: "Tenant ID" },
  { key: "details", label: "Details (JSON)" },
] as const;

type ColumnKey = (typeof EXPORT_COLUMNS)[number]["key"];

const EXPORT_QUERY = `
  query AuditLogsExport(
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

type AuditLogItem = {
  id: string;
  event: string;
  outcome: string;
  entityId: string | null;
  tenantId: string | null;
  details: Record<string, unknown>;
  createdAt: string;
};

// ─── CSV helpers ──────────────────────────────────────────────────────────────

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = typeof value === "object" ? JSON.stringify(value) : String(value);
  // Wrap in quotes and escape any internal quotes
  return `"${str.replace(/"/g, '""')}"`;
}

function buildCsv(items: AuditLogItem[], columns: ColumnKey[]): string {
  const header = columns
    .map((k) => EXPORT_COLUMNS.find((c) => c.key === k)?.label ?? k)
    .map(csvCell)
    .join(",");
  const rows = items.map((item) =>
    columns.map((k) => csvCell(item[k as keyof AuditLogItem])).join(","),
  );
  return [header, ...rows].join("\n");
}

function triggerDownload(csv: string, filename: string) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ────────────────────────────────────────────────────────────────

type Props = {
  /** Pre-populate filter fields from the current page view. */
  defaultEvent?: string;
  defaultOutcome?: string;
  defaultFrom?: string;
  defaultTo?: string;
};

export function AuditExportDialog({
  defaultEvent = "",
  defaultOutcome = "",
  defaultFrom = "",
  defaultTo = "",
}: Props) {
  const [open, setOpen] = React.useState(false);
  const { selection } = useTenant();

  // Column selection — all on by default
  const [selectedColumns, setSelectedColumns] = React.useState<Set<ColumnKey>>(
    new Set(EXPORT_COLUMNS.map((c) => c.key)),
  );

  // Export-specific filters (pre-populated from current view)
  const [event, setEvent] = React.useState(defaultEvent);
  const [outcome, setOutcome] = React.useState(defaultOutcome);
  const [from, setFrom] = React.useState(defaultFrom);
  const [to, setTo] = React.useState(defaultTo);
  const [limit, setLimit] = React.useState(500);
  const [offset, setOffset] = React.useState(0);

  // Sync defaults when dialog opens
  React.useEffect(() => {
    if (open) {
      setEvent(defaultEvent);
      setOutcome(defaultOutcome);
      setFrom(defaultFrom);
      setTo(defaultTo);
    }
  }, [open, defaultEvent, defaultOutcome, defaultFrom, defaultTo]);

  function toggleColumn(key: ColumnKey) {
    setSelectedColumns((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  function selectAll() {
    setSelectedColumns(new Set(EXPORT_COLUMNS.map((c) => c.key)));
  }

  function selectNone() {
    setSelectedColumns(new Set());
  }

  const exportMutation = useMutation({
    mutationFn: async () => {
      const columns = EXPORT_COLUMNS.map((c) => c.key).filter((k) =>
        selectedColumns.has(k),
      );
      if (columns.length === 0) throw new Error("Select at least one column.");

      const clampedLimit = Math.min(Math.max(1, limit), MAX_EXPORT_ROWS);
      const batches = Math.ceil(clampedLimit / BATCH_SIZE);
      const allItems: AuditLogItem[] = [];

      for (let i = 0; i < batches; i++) {
        const batchOffset = offset + i * BATCH_SIZE;
        const batchLimit = Math.min(BATCH_SIZE, clampedLimit - i * BATCH_SIZE);
        const data = await graphqlClient<{
          auditLogs: { items: AuditLogItem[] };
        }>({
          query: EXPORT_QUERY,
          variables: {
            limit: batchLimit,
            offset: batchOffset,
            event: event || undefined,
            outcome: outcome || undefined,
            from: from || undefined,
            to: to || undefined,
            tenantId: tenantQueryValue(selection) ?? undefined,
          },
        });
        allItems.push(...(data.auditLogs.items ?? []));
        if (data.auditLogs.items.length < batchLimit) break;
      }

      const csv = buildCsv(allItems, columns);
      const ts = new Date().toISOString().slice(0, 10);
      triggerDownload(csv, `audit-logs-${ts}.csv`);
      return allItems.length;
    },
    onSuccess: (count) => {
      setOpen(false);
      // brief reset so next open starts fresh
      void count;
    },
  });

  const orderedColumns = EXPORT_COLUMNS.map((c) => c.key).filter((k) =>
    selectedColumns.has(k),
  );

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs">
          <Download className="size-3.5" />
          Export CSV
        </Button>
      </DialogTrigger>

      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Export audit logs</DialogTitle>
          <DialogDescription>
            Choose the columns and filters for your CSV download. Up to{" "}
            {MAX_EXPORT_ROWS.toLocaleString()} rows are fetched in batches of{" "}
            {BATCH_SIZE}.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-5">
          {/* ── Columns ── */}
          <div className="grid gap-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Columns</span>
              <div className="flex gap-2 text-xs">
                <button
                  type="button"
                  onClick={selectAll}
                  className="text-primary hover:underline"
                >
                  All
                </button>
                <span className="text-muted-foreground">·</span>
                <button
                  type="button"
                  onClick={selectNone}
                  className="text-primary hover:underline"
                >
                  None
                </button>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {EXPORT_COLUMNS.map((col) => (
                <label
                  key={col.key}
                  className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted/50 has-data-checked:border-primary has-[[data-checked]]:bg-primary/5"
                >
                  <Checkbox
                    checked={selectedColumns.has(col.key)}
                    onCheckedChange={() => toggleColumn(col.key)}
                  />
                  {col.label}
                </label>
              ))}
            </div>
            {selectedColumns.size === 0 ? (
              <p className="text-xs text-destructive">
                Select at least one column.
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                {orderedColumns.length} column
                {orderedColumns.length !== 1 ? "s" : ""} selected
              </p>
            )}
          </div>

          <Separator />

          {/* ── Filters ── */}
          <div className="grid gap-3">
            <span className="text-sm font-medium">Filters</span>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label className="text-xs">Event</Label>
                <Input
                  placeholder="e.g. authz.check"
                  value={event}
                  onChange={(e) => setEvent(e.target.value)}
                  className="h-8 text-sm"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">Outcome</Label>
                <Select
                  value={outcome || NONE}
                  onValueChange={(v) => setOutcome(v === NONE ? "" : v)}
                >
                  <SelectTrigger className="h-8 text-sm">
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
              <div className="grid gap-1.5">
                <Label className="text-xs">From</Label>
                <DateTimePicker
                  value={from || undefined}
                  onChange={setFrom}
                  placeholder="From date & time"
                  className="h-8 text-sm"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">To</Label>
                <DateTimePicker
                  value={to || undefined}
                  onChange={setTo}
                  placeholder="To date & time"
                  className="h-8 text-sm"
                />
              </div>
            </div>
          </div>

          <Separator />

          {/* ── Pagination ── */}
          <div className="grid gap-3">
            <span className="text-sm font-medium">Pagination</span>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label className="text-xs">
                  Limit{" "}
                  <span className="text-muted-foreground">
                    (max {MAX_EXPORT_ROWS.toLocaleString()})
                  </span>
                </Label>
                <Input
                  type="number"
                  min={1}
                  max={MAX_EXPORT_ROWS}
                  value={limit}
                  onChange={(e) =>
                    setLimit(
                      Math.min(
                        MAX_EXPORT_ROWS,
                        Math.max(1, Number(e.target.value) || 1),
                      ),
                    )
                  }
                  className="h-8 text-sm"
                />
              </div>
              <div className="grid gap-1.5">
                <Label className="text-xs">Offset</Label>
                <Input
                  type="number"
                  min={0}
                  value={offset}
                  onChange={(e) =>
                    setOffset(Math.max(0, Number(e.target.value) || 0))
                  }
                  className="h-8 text-sm"
                />
              </div>
            </div>
          </div>
        </div>

        <DialogFooter>
          {exportMutation.isError ? (
            <p className="mr-auto text-xs text-destructive">
              {(exportMutation.error as Error).message}
            </p>
          ) : null}
          <Button
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending || selectedColumns.size === 0}
          >
            {exportMutation.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Downloading…
              </>
            ) : (
              <>
                <Download className="size-4" />
                Download CSV
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
