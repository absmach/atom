import { Lock } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * Renders "Config" when a row was provisioned from the Atom bootstrap YAML.
 * Rows carrying `managed_by='config'` are read-only through the API —
 * update/delete/revoke calls return 409 conflict — so the UI surfaces this
 * marker and disables their mutation buttons.
 */
export function ManagedByBadge({
  managedBy,
  className,
}: {
  managedBy?: string | null;
  className?: string;
}) {
  if (managedBy !== "config") return null;
  return (
    <span
      className={cn(
        "inline-flex h-5 w-fit shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        "border-slate-500/40 bg-slate-500/10 text-slate-700 dark:border-slate-400/40 dark:text-slate-300",
        className,
      )}
      title="Managed by the bootstrap config file — read-only through the API"
    >
      <Lock className="h-3 w-3" aria-hidden />
      Config
    </span>
  );
}

/** Row-shape predicate: true when the row must be shown read-only in the UI. */
export function isConfigManaged(row: { managedBy?: string | null }): boolean {
  return row.managedBy === "config";
}

/** Tooltip text for a disabled button on a config-managed row. */
export const CONFIG_MANAGED_TOOLTIP =
  "Managed by the bootstrap config file. Edit the YAML and restart Atom to change.";
