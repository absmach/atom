import * as React from "react";
import {
  formatDetailValue,
  isTimeColumn,
  isValidTime,
  timeActionForColumn,
} from "@/components/crud/table/cell-rendering";
import type { Row } from "@/components/crud/table/types";
import { DisplayTimeCell } from "@/components/display-time";
import { JsonEditor } from "@/components/ui/json-editor";
import { DisplayTags } from "@/components/view-tags";

export function DetailFields({ row }: { row: Row | null }) {
  return (
    <>
      {row
        ? Object.entries(row).map(([key, value]) => (
            <div
              className="grid gap-1 rounded-lg border bg-background p-3"
              key={key}
            >
              <div className="text-xs font-medium uppercase text-muted-foreground">
                {key}
              </div>
              <DetailFieldValue fieldKey={key} value={value} />
            </div>
          ))
        : null}
    </>
  );
}

function DetailFieldValue({
  fieldKey,
  value,
}: {
  fieldKey: string;
  value: unknown;
}) {
  if (fieldKey === "tags" && Array.isArray(value)) {
    return value.length ? (
      <DisplayTags
        className="max-w-full"
        tags={value.map((item) => String(item))}
      />
    ) : (
      <span className="text-muted-foreground">-</span>
    );
  }

  if (fieldKey === "attributes" && value && typeof value === "object") {
    return (
      <JsonSchemaViewer label="Attributes" showLabel={false} value={value} />
    );
  }

  if (
    isTimeColumn(fieldKey) &&
    typeof value === "string" &&
    isValidTime(value)
  ) {
    return (
      <DisplayTimeCell action={timeActionForColumn(fieldKey)} time={value} />
    );
  }

  return (
    <div className="wrap-break-word font-mono text-xs">
      {formatDetailValue(value)}
    </div>
  );
}

function JsonSchemaViewer({
  label,
  showLabel = true,
  value,
}: {
  label: string;
  showLabel?: boolean;
  value: unknown;
}) {
  const code = React.useMemo(() => JSON.stringify(value, null, 2), [value]);

  return (
    <div className="grid min-w-0 max-w-full gap-2">
      {showLabel ? (
        <div className="text-xs font-medium uppercase text-muted-foreground">
          {label}
        </div>
      ) : null}
      <JsonEditor value={code} className="[&_.cm-editor]:min-h-48" />
    </div>
  );
}
