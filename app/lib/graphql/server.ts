import { AtomGraphqlError, getGraphqlEndpoint } from "@/lib/graphql/client";
import { getServerToken } from "@/lib/auth/session";

type ServerGraphqlRequest = {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
};

export async function graphqlServer<TData>({
  query,
  variables,
  operationName,
}: ServerGraphqlRequest): Promise<TData> {
  const token = await getServerToken();
  const response = await fetch(getGraphqlEndpoint(), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ query, variables, operationName }),
    cache: "no-store",
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
