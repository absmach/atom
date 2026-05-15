export type GraphqlError = {
  message: string;
  path?: Array<string | number>;
};

export class AtomGraphqlError extends Error {
  errors: GraphqlError[];

  constructor(errors: GraphqlError[]) {
    super(errors.map((error) => error.message).join("; "));
    this.name = "AtomGraphqlError";
    this.errors = errors;
  }
}

export type GraphqlRequest = {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
  signal?: AbortSignal;
};

export async function graphqlClient<TData>({
  query,
  variables,
  operationName,
  signal,
}: GraphqlRequest): Promise<TData> {
  const response = await fetch("/api/graphql", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables, operationName }),
    signal,
  });

  const payload = await response.json();
  if (!response.ok || payload.errors?.length) {
    throw new AtomGraphqlError(
      payload.errors ?? [
        { message: payload.message ?? "GraphQL request failed" },
      ],
    );
  }

  return payload.data as TData;
}

export function getGraphqlEndpoint() {
  return process.env.ATOM_GRAPHQL_URL ?? "http://localhost:8081/graphql";
}
