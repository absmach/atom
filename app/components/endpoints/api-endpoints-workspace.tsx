import { Database } from "lucide-react";

import { ApiEndpointsTable } from "@/components/endpoints/api-endpoints-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { graphqlServer } from "@/lib/graphql/server";

const LIMIT = 50;

export type ApiEndpointRow = {
  id: string;
  tenantId: string | null;
  key: string;
  name: string;
  description: string | null;
  method: string;
  path: string;
  operationKind: string;
  graphql: string;
  authMode: string;
  serviceEntityId: string | null;
  variablesMapping: unknown;
  requestSchema: unknown;
  responseMapping: unknown;
  status: string;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
};

const ENDPOINTS_QUERY = `
  query ApiEndpoints($limit: Int, $offset: Int) {
    apiEndpoints(limit: $limit, offset: $offset) {
      total
      items {
        id tenantId key name description method path operationKind graphql
        authMode serviceEntityId variablesMapping requestSchema responseMapping
        status createdBy updatedBy createdAt updatedAt
      }
    }
  }
`;

export async function ApiEndpointsWorkspace({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>;
}) {
  const rawPage = searchParams["endpoints.page"];
  const page = Math.max(
    1,
    Number(Array.isArray(rawPage) ? rawPage[0] : (rawPage ?? "1")) || 1,
  );
  const offset = (page - 1) * LIMIT;

  let rows: ApiEndpointRow[] = [];
  let total = 0;
  let fetchError: Error | null = null;

  try {
    const endpointsData = await graphqlServer<{
      apiEndpoints: { items: ApiEndpointRow[]; total: number };
    }>({
      query: ENDPOINTS_QUERY,
      variables: { limit: LIMIT, offset },
    });
    rows = endpointsData.apiEndpoints.items;
    total = endpointsData.apiEndpoints.total;
  } catch (err) {
    fetchError = err instanceof Error ? err : new Error("Data request failed");
  }

  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            API Endpoints
          </h1>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Custom HTTP routes backed by Atom GraphQL operations, request
          validation, response mapping, and execution auth controls.
        </p>
      </div>

      {fetchError ? (
        <Alert variant="destructive">
          <Database className="size-4" />
          <AlertTitle>Failed to load endpoints</AlertTitle>
          <AlertDescription>{fetchError.message}</AlertDescription>
        </Alert>
      ) : null}

      <ApiEndpointsTable limit={LIMIT} page={page} rows={rows} total={total} />
    </section>
  );
}
