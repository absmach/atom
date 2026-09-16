// Stable GraphQL error contract (issue #101). Every Atom-generated GraphQL
// error carries `extensions.code`/`retryable`/`requestId`; see
// `api/v1/graphql-error-contract.md` for the full contract this file
// decodes. `message` is human-readable but not a stable API — never branch
// on it; branch on `extensions.code`.
export type GraphqlErrorCode =
  | "BAD_REQUEST"
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "PAYLOAD_TOO_LARGE"
  | "RATE_LIMITED"
  | "SERVICE_UNAVAILABLE"
  | "INTERNAL";

export type GraphqlErrorExtensions = {
  code?: GraphqlErrorCode | (string & {});
  retryable?: boolean;
  requestId?: string;
  retryAfterSeconds?: number;
};

export type GraphqlError = {
  message: string;
  path?: Array<string | number>;
  extensions?: GraphqlErrorExtensions;
};

export class AtomGraphqlError extends Error {
  errors: GraphqlError[];
  /** The correlating `X-Request-ID`, when at least one error carried one. */
  requestId?: string;

  constructor(errors: GraphqlError[]) {
    super(errors.map((error) => error.message).join("; "));
    this.name = "AtomGraphqlError";
    this.errors = errors;
    this.requestId = errors.find(
      (error) => error.extensions?.requestId,
    )?.extensions?.requestId;
  }
}

/**
 * Whether `error` is an Atom GraphQL error carrying a `FORBIDDEN` code.
 * Detects by `extensions.code`, never by message text — message is not a
 * stable API (issue #101).
 */
export function isForbiddenError(error: unknown) {
  return (
    error instanceof AtomGraphqlError &&
    error.errors.some((entry) => entry.extensions?.code === "FORBIDDEN")
  );
}

/** The `extensions.code` of the first error, if `error` is an Atom GraphQL error. */
export function graphqlErrorCode(error: unknown): GraphqlErrorCode | undefined {
  if (!(error instanceof AtomGraphqlError)) return undefined;
  const code = error.errors[0]?.extensions?.code;
  return code as GraphqlErrorCode | undefined;
}

/** Whether retrying the identical request might succeed, per `extensions.retryable`. */
export function isRetryableError(error: unknown) {
  return (
    error instanceof AtomGraphqlError &&
    error.errors.some((entry) => entry.extensions?.retryable === true)
  );
}

export type GraphqlRequest = {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
  signal?: AbortSignal;
};

export type GraphqlRawResult<TData> = {
  data: TData | null;
  errors: GraphqlError[];
};

/**
 * Parses a GraphQL HTTP response body into `{data, errors}`, normalizing a
 * response that isn't even a GraphQL envelope (a proxy error page, an empty
 * body) into a single synthetic error carrying no `extensions.code` — the
 * client genuinely doesn't have one to report, and this shape is still safe
 * for `isForbiddenError`/`graphqlErrorCode` to receive (issue #101: "transport
 * failures without a GraphQL envelope are normalized safely").
 */
function parseGraphqlPayload<TData>(payload: unknown): GraphqlRawResult<TData> {
  if (
    payload === null ||
    typeof payload !== "object" ||
    (!("data" in payload) && !("errors" in payload))
  ) {
    return {
      data: null,
      errors: [{ message: "GraphQL request failed: malformed response" }],
    };
  }
  const record = payload as { data?: TData; errors?: GraphqlError[] };
  return { data: record.data ?? null, errors: record.errors ?? [] };
}

/**
 * Shared transport for both the browser and server GraphQL clients (issue
 * #101 requires identical decoding behavior for each) — issues `fetch`,
 * parses the JSON body, and normalizes it to `{data, errors}`, never
 * throwing on a GraphQL-level (as opposed to network-level) error.
 */
export async function fetchGraphqlRaw<TData>(
  url: string,
  init: RequestInit,
): Promise<GraphqlRawResult<TData>> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (cause) {
    const message =
      cause instanceof Error ? cause.message : "GraphQL request failed";
    return { data: null, errors: [{ message }] };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return {
      data: null,
      errors: [
        {
          message: `GraphQL request failed with status ${response.status}`,
        },
      ],
    };
  }

  const result = parseGraphqlPayload<TData>(payload);
  if (!response.ok && result.errors.length === 0) {
    return {
      data: null,
      errors: [
        {
          message:
            (payload as { message?: string })?.message ??
            `GraphQL request failed with status ${response.status}`,
        },
      ],
    };
  }
  return result;
}

/**
 * Executes a GraphQL request and returns `{data, errors}` without throwing —
 * for callers that deliberately consume partial data alongside errors in the
 * same response (issue #101). Prefer `graphqlClient` for the common
 * all-or-nothing case.
 */
export async function graphqlClientRaw<TData>({
  query,
  variables,
  operationName,
  signal,
}: GraphqlRequest): Promise<GraphqlRawResult<TData>> {
  return fetchGraphqlRaw<TData>("/api/graphql", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ query, variables, operationName }),
    signal,
  });
}

/**
 * Executes a GraphQL request; throws `AtomGraphqlError` if the response
 * carries any error, discarding partial data — the common case. Use
 * `graphqlClientRaw` when the caller wants partial data even on error.
 */
export async function graphqlClient<TData>(
  request: GraphqlRequest,
): Promise<TData> {
  const { data, errors } = await graphqlClientRaw<TData>(request);
  if (errors.length > 0) {
    throw new AtomGraphqlError(errors);
  }
  return data as TData;
}

export function getGraphqlEndpoint() {
  return process.env.ATOM_GRAPHQL_URL ?? "http://localhost:8080/graphql";
}

export function getBackendBaseUrl() {
  return getGraphqlEndpoint().replace(/\/graphql\/?$/, "");
}
