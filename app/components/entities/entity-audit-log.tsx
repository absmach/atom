"use client";

import { useQuery } from "@tanstack/react-query";
import * as React from "react";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { graphqlClient } from "@/lib/graphql/client";

const ENTITY_AUDIT_QUERY = `
  query EntityAuditLogs($entityId: ID!, $limit: Int, $offset: Int) {
    auditLogs(entityId: $entityId, limit: $limit, offset: $offset) {
      total
      items {
        id
        event
        outcome
        createdAt
      }
    }
  }
`;

type AuditItem = {
  id: string;
  event: string;
  outcome: string;
  createdAt: string;
};

type AuditResponse = {
  auditLogs: { total: number; items: AuditItem[] };
};

const PAGE_SIZE = 10;

export function EntityAuditLog({ entityId }: { entityId: string }) {
  const [page, setPage] = React.useState(1);
  const offset = (page - 1) * PAGE_SIZE;

  const { data, isFetching, error } = useQuery({
    queryKey: ["entity-audit", entityId, page],
    queryFn: ({ signal }) =>
      graphqlClient<AuditResponse>({
        query: ENTITY_AUDIT_QUERY,
        variables: { entityId, limit: PAGE_SIZE, offset },
        signal,
      }),
    staleTime: 15_000,
    placeholderData: (prev) => prev,
  });

  const items = data?.auditLogs.items ?? [];
  const total = data?.auditLogs.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        {error.message}
      </div>
    );
  }

  if (!isFetching && items.length === 0) {
    return (
      <div className="rounded-lg border bg-muted/30 p-4 text-center text-sm text-muted-foreground">
        No audit logs for this entity.
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>Outcome</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isFetching && items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3} className="text-center text-muted-foreground text-sm">
                  Loading…
                </TableCell>
              </TableRow>
            ) : (
              items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="text-xs">
                    <DisplayTimeCell time={item.createdAt} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{item.event}</TableCell>
                  <TableCell>
                    <StatusBadge value={item.outcome} />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 ? (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            Page {page} of {totalPages} · {total} total
          </span>
          <div className="flex gap-2">
            <Button
              disabled={page <= 1 || isFetching}
              onClick={() => setPage((p) => p - 1)}
              size="sm"
              variant="outline"
            >
              Previous
            </Button>
            <Button
              disabled={page >= totalPages || isFetching}
              onClick={() => setPage((p) => p + 1)}
              size="sm"
              variant="outline"
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
