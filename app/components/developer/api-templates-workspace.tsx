import { Database } from "lucide-react";

import { ApiTemplatesTable } from "@/components/developer/api-templates-table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { graphqlServer } from "@/lib/graphql/server";

const LIMIT = 50;

export type ApiTemplateRow = {
  id: string;
  tenantId: string | null;
  key: string;
  name: string;
  description: string | null;
  operationKind: string;
  graphql: string;
  variablesSchema: unknown;
  defaultVariables: unknown;
  resultSelector: unknown;
  tags: string[];
  status: string;
  createdAt: string;
  updatedAt: string;
};

const LIST_QUERY = `
  query ApiTemplates($limit: Int, $offset: Int) {
    apiTemplates(limit: $limit, offset: $offset) {
      total
      items {
        id tenantId key name description operationKind graphql
        variablesSchema defaultVariables resultSelector tags status
        createdAt updatedAt
      }
    }
  }
`;

export async function ApiTemplatesWorkspace({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>;
}) {
  const rawPage = searchParams["templates.page"];
  const page = Math.max(
    1,
    Number(Array.isArray(rawPage) ? rawPage[0] : (rawPage ?? "1")) || 1,
  );
  const offset = (page - 1) * LIMIT;

  let rows: ApiTemplateRow[] = [];
  let total = 0;
  let fetchError: Error | null = null;

  try {
    const data = await graphqlServer<{
      apiTemplates: { items: ApiTemplateRow[]; total: number };
    }>({ query: LIST_QUERY, variables: { limit: LIMIT, offset } });
    rows = data.apiTemplates.items;
    total = data.apiTemplates.total;
  } catch (err) {
    fetchError = err instanceof Error ? err : new Error("Data request failed");
  }

  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            API Templates
          </h1>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Reusable operation blueprints that power API endpoints.
        </p>
      </div>

      {fetchError ? (
        <Alert variant="destructive">
          <Database className="size-4" />
          <AlertTitle>Failed to load templates</AlertTitle>
          <AlertDescription>{fetchError.message}</AlertDescription>
        </Alert>
      ) : null}

      <ApiTemplatesTable limit={LIMIT} page={page} rows={rows} total={total} />
    </section>
  );
}
