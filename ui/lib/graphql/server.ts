import { getServerToken } from "@/lib/auth/session";
import {
  AtomGraphqlError,
  fetchGraphqlRaw,
  type GraphqlRawResult,
  getGraphqlEndpoint,
} from "@/lib/graphql/client";

type ServerGraphqlRequest = {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
};

async function serverInit(): Promise<RequestInit> {
  const token = await getServerToken();
  return {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    cache: "no-store",
  };
}

/**
 * Server-side counterpart to `graphqlClientRaw` — same decoding behavior
 * (issue #101), for callers that want partial data alongside errors instead
 * of an all-or-nothing throw.
 */
export async function graphqlServerRaw<TData>({
  query,
  variables,
  operationName,
}: ServerGraphqlRequest): Promise<GraphqlRawResult<TData>> {
  const init = await serverInit();
  return fetchGraphqlRaw<TData>(getGraphqlEndpoint(), {
    ...init,
    body: JSON.stringify({ query, variables, operationName }),
  });
}

export async function graphqlServer<TData>(
  request: ServerGraphqlRequest,
): Promise<TData> {
  const { data, errors } = await graphqlServerRaw<TData>(request);
  if (errors.length > 0) {
    throw new AtomGraphqlError(errors);
  }
  return data as TData;
}
