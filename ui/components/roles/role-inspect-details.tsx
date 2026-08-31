"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, Copy } from "lucide-react";
import * as React from "react";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const TENANT_QUERY = `
  query RoleInspectTenant($id: ID!) {
    tenant(id: $id) { id name }
  }
`;

type Row = Record<string, unknown>;

export function RoleInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);

  const id = row?.id ? String(row.id) : "";
  const tenantId = row?.tenantId ? String(row.tenantId) : "";

  const tenantQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ["role-inspect-tenant", tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenant: { id: string; name: string } }>({
        query: TENANT_QUERY,
        variables: { id: tenantId },
        signal,
      }),
    staleTime: 60_000,
  });

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  const tenantName = tenantQuery.data?.tenant.name ?? tenantId;

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

      {row.name ? (
        <Field label="Name">
          <span className="text-sm">{String(row.name)}</span>
        </Field>
      ) : null}

      <Field label="Tenant">
        <span className="text-sm">
          {tenantId ? tenantName : "— platform —"}
        </span>
      </Field>

      {row.derivedKind ? (
        <Field label="Derived kind">
          <span className="text-sm">{String(row.derivedKind)}</span>
        </Field>
      ) : null}

      {row.description ? (
        <Field label="Description">
          <span className="text-sm">{String(row.description)}</span>
        </Field>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
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
