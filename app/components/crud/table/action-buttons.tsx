import type {
  ENTITY_STATUS_MUTATIONS,
  TENANT_STATUS_MUTATIONS,
} from "@/components/crud/table/constants";
import type { Row } from "@/components/crud/table/types";
import { Button } from "@/components/ui/button";

export function TenantActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (action: keyof typeof TENANT_STATUS_MUTATIONS) => void;
  row: Row;
}) {
  const status = String(row.status ?? "");

  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <>
          <Button
            disabled={isPending}
            onClick={() => onStatusChange("freeze")}
            size="sm"
            variant="outline"
            className="border-blue-500/50 text-blue-600 hover:bg-blue-500/10 hover:text-blue-600 dark:border-blue-500/40 dark:text-blue-400"
          >
            Freeze
          </Button>
          <Button
            disabled={isPending}
            onClick={() => onStatusChange("disable")}
            size="sm"
            variant="outline"
            className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
          >
            Disable
          </Button>
        </>
      ) : (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("enable")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      )}
    </>
  );
}

export function EntityActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (action: keyof typeof ENTITY_STATUS_MUTATIONS) => void;
  row: Row;
}) {
  const status = String(row.status ?? "");
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("disable")}
          size="sm"
          variant="outline"
          className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
        >
          Disable
        </Button>
      ) : (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("enable")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      )}
    </>
  );
}

export function ProfileActionButtons({
  isPending,
  onEdit,
  onStatusChange,
  row,
}: {
  isPending: boolean;
  onEdit: () => void;
  onStatusChange: (status: "active" | "disabled") => void;
  row: Row;
}) {
  const status = String(row.status ?? "");
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      {status === "active" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("disabled")}
          size="sm"
          variant="outline"
          className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
        >
          Disable
        </Button>
      ) : status === "disabled" || status === "deprecated" ? (
        <Button
          disabled={isPending}
          onClick={() => onStatusChange("active")}
          size="sm"
          variant="outline"
          className="border-green-500/50 text-green-600 hover:bg-green-500/10 hover:text-green-600 dark:border-green-500/40 dark:text-green-400"
        >
          Enable
        </Button>
      ) : null}
    </>
  );
}

export function DeleteActionButtons({
  isDestroyPending,
  onEdit,
  onDelete,
}: {
  isDestroyPending: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <Button onClick={onEdit} size="sm" variant="outline">
        Edit
      </Button>
      <Button
        disabled={isDestroyPending}
        onClick={onDelete}
        size="sm"
        variant="outline"
        className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:border-red-500/40 dark:text-red-400"
      >
        Delete
      </Button>
    </>
  );
}
