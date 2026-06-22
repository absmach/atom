"use client";

import { Check, Copy } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import { Action } from "@/lib/utils";

type Row = Record<string, unknown>;

export function CapabilityInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);

  const id = row?.id ? String(row.id) : "";

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  return (
    <div className="grid gap-3">
      <Field label="ID">
        <div className="flex items-center gap-2">
          <span className="break-all font-mono text-xs">{id}</span>
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

      {row.actionName || row.capabilityName ? (
        <Field label="action_name">
          <span className="text-sm">
            {String(row.actionName ?? row.capabilityName)}
          </span>
        </Field>
      ) : row.name ? (
        <Field label="name">
          <span className="text-sm">{String(row.name)}</span>
        </Field>
      ) : null}

      {row.actionId || row.capabilityId ? (
        <Field label="action_id">
          <span className="break-all font-mono text-xs">
            {String(row.actionId ?? row.capabilityId)}
          </span>
        </Field>
      ) : null}

      {row.objectKind ? (
        <Field label="object_kind">
          <span className="font-mono text-xs">{String(row.objectKind)}</span>
        </Field>
      ) : null}

      {row.objectType !== undefined ? (
        <Field label="object_type">
          <span className="font-mono text-xs">
            {row.objectType ? String(row.objectType) : "NULL"}
          </span>
        </Field>
      ) : null}

      {row.description ? (
        <Field label="Description">
          <span className="text-sm">{String(row.description)}</span>
        </Field>
      ) : null}

      {row.createdAt ? (
        <Field label="Created">
          <DisplayTimeCell
            action={Action.Created}
            time={String(row.createdAt)}
          />
        </Field>
      ) : null}
      {row.updatedAt ? (
        <Field label="Updated">
          <DisplayTimeCell
            action={Action.Updated}
            time={String(row.updatedAt)}
          />
        </Field>
      ) : null}
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
