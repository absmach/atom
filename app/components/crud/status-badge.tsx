import { cn } from "@/lib/utils";

const BASE =
  "inline-flex h-5 w-fit shrink-0 items-center justify-center rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap";

function statusClass(normalized: string): string {
  switch (normalized) {
    case "active":
    case "allow":
      return "border-green-500/40 bg-green-500/10 text-green-700 dark:border-green-400/40 dark:text-green-400";
    case "disabled":
    case "deny":
    case "suspended":
    case "revoked":
      return "border-red-500/40 bg-red-500/10 text-red-700 dark:border-red-400/40 dark:text-red-400";
    case "deprecated":
      return "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:border-amber-400/40 dark:text-amber-400";
    case "frozen":
      return "border-blue-500/40 bg-blue-500/10 text-blue-700 dark:border-blue-400/40 dark:text-blue-400";
    case "inactive":
    case "draft":
    default:
      return "border-border bg-muted text-muted-foreground";
  }
}

export function StatusBadge({ value }: { value: unknown }) {
  const text = String(value ?? "");

  if (!text) return null;
  return (
    <span className={cn(BASE, statusClass(text.toLowerCase()))}>{text}</span>
  );
}
