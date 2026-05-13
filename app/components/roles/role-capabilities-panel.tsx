"use client";

import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { graphqlClient } from "@/lib/graphql/client";

const ROLE_CAPABILITIES_QUERY = `
  query RoleCapabilitiesPanel($roleId: ID!) {
    roleCapabilities(roleId: $roleId) { id name resourceKind description }
  }
`;

type GqlCapability = {
  id: string;
  name: string;
  resourceKind: string | null;
  description: string | null;
};

export function RoleCapabilitiesPanel({ roleId }: { roleId: string }) {
  const { data, isFetching, error } = useQuery({
    queryKey: ["role-capabilities-panel", roleId],
    queryFn: ({ signal }) =>
      graphqlClient<{ roleCapabilities: GqlCapability[] }>({
        query: ROLE_CAPABILITIES_QUERY,
        variables: { roleId },
        signal,
      }),
    staleTime: 30_000,
  });

  const capabilities = data?.roleCapabilities ?? [];

  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="text-sm font-medium">Capabilities</div>
      {isFetching && capabilities.length === 0 ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : error ? (
        <p className="text-sm text-destructive">{error.message}</p>
      ) : capabilities.length === 0 ? (
        <p className="text-sm text-muted-foreground">No capabilities assigned to this role.</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {capabilities.map((cap) => (
            <Badge key={cap.id} variant="secondary" title={cap.description ?? undefined}>
              {cap.name}
              {cap.resourceKind ? (
                <span className="ml-1 text-muted-foreground">:{cap.resourceKind}</span>
              ) : null}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
