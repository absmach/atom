import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { DisplayTags } from "@/components/view-tags";
import { Action } from "@/lib/utils";

const RESOLVABLE_FIELDS = new Set([
  "tenantId",
  "profileId",
  "ownerId",
  "subjectId",
  "grantId",
  "scopeRef",
]);

export function renderCell(
  value: unknown,
  key?: string,
  nameMap?: Map<string, string>,
) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">-</span>;
  }
  if (
    nameMap &&
    key &&
    RESOLVABLE_FIELDS.has(key) &&
    typeof value === "string"
  ) {
    const resolved = nameMap.get(value);
    if (resolved) return <span className="text-sm">{resolved}</span>;
  }
  if (
    key &&
    isTimeColumn(key) &&
    typeof value === "string" &&
    isValidTime(value)
  ) {
    return <DisplayTimeCell action={timeActionForColumn(key)} time={value} />;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-muted-foreground">-</span>;
    }
    return (
      <DisplayTags
        className="max-w-72"
        tags={value.map((item) =>
          typeof item === "object" && item !== null && "name" in item
            ? String(item.name)
            : String(item),
        )}
      />
    );
  }
  if (
    [
      "active",
      "inactive",
      "suspended",
      "allow",
      "deny",
      "disabled",
      "frozen",
      "deprecated",
    ].includes(String(value))
  ) {
    return <StatusBadge value={value} />;
  }
  if (key === "description") {
    return (
      <span className="block max-w-72 whitespace-normal wrap-break-word text-sm">
        {String(value)}
      </span>
    );
  }
  if (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      String(value),
    )
  ) {
    return (
      <div className="w-40 font-mono text-xs break-all">{String(value)}</div>
    );
  }
  if (String(value).length > 44) {
    return (
      <div className="w-40 font-mono text-xs break-all">{String(value)}</div>
    );
  }
  return <span>{String(value)}</span>;
}

export function formatDetailValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}

export function isTimeColumn(key: string) {
  return (
    key === "createdAt" ||
    key === "updatedAt" ||
    key === "expiresAt" ||
    key === "lastUsedAt"
  );
}

export function isValidTime(value: string) {
  return !Number.isNaN(Date.parse(value));
}

export function timeActionForColumn(key: string) {
  switch (key) {
    case "updatedAt":
      return Action.Updated;
    case "expiresAt":
      return Action.Expired;
    case "lastUsedAt":
      return Action.LastUsed;
    case "createdAt":
      return Action.Created;
    default:
      return Action.Created;
  }
}
