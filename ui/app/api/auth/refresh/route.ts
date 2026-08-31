import { NextResponse } from "next/server";
import {
  AUTH_COOKIE,
  AUTH_META_COOKIE,
  type AuthCookiePayload,
  getServerToken,
  setAuthCookies,
} from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

const REFRESH_MUTATION = `
mutation RefreshSession {
  refreshSession {
    token
    entityId
    sessionId
    expiresAt
  }
}
`;

type GraphqlPayload = {
  data?: {
    refreshSession?: unknown;
  };
  errors?: Array<{ message?: string }>;
  message?: string;
};

export async function POST(request: Request) {
  const token = await getServerToken();
  if (!token) {
    return clearAuth(
      NextResponse.json({ message: "missing authentication" }, { status: 401 }),
    );
  }

  let response: Response;
  try {
    response = await fetch(getGraphqlEndpoint(), {
      method: "POST",
      headers: withForwardedClientIpHeaders(request, {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      }),
      body: JSON.stringify({
        query: REFRESH_MUTATION,
        operationName: "RefreshSession",
      }),
    });
  } catch {
    return NextResponse.json(
      { message: "Session refresh failed" },
      { status: 502 },
    );
  }

  const payload = (await response
    .json()
    .catch(() => null)) as GraphqlPayload | null;
  const message =
    payload?.errors?.[0]?.message ??
    payload?.message ??
    "Session refresh failed";

  if (!response.ok || payload?.errors?.length) {
    const status = isAuthFailure(message) ? 401 : 502;
    const res = NextResponse.json({ message }, { status });
    return status === 401 ? clearAuth(res) : res;
  }

  const refreshResult = payload?.data?.refreshSession;
  if (!isAuthCookiePayload(refreshResult)) {
    return NextResponse.json(
      { message: "Session refresh failed" },
      { status: 502 },
    );
  }

  const refreshed = refreshResult;
  const res = NextResponse.json({
    entityId: refreshed.entityId,
    sessionId: refreshed.sessionId,
    expiresAt: refreshed.expiresAt,
  });
  setAuthCookies(res, refreshed);
  return res;
}

function clearAuth(response: NextResponse) {
  response.cookies.delete(AUTH_COOKIE);
  response.cookies.delete(AUTH_META_COOKIE);
  return response;
}

function isAuthFailure(message: string) {
  return [
    "missing authentication",
    "session refresh requires a session token",
    "session is not refreshable",
    "session not found",
    "session revoked",
    "session expired",
    "invalid token",
    "entity is not active",
    "tenant is not active",
  ].some((needle) => message.includes(needle));
}

function isAuthCookiePayload(value: unknown): value is AuthCookiePayload {
  if (!isRecord(value)) return false;
  return (
    typeof value.token === "string" &&
    typeof value.entityId === "string" &&
    typeof value.sessionId === "string" &&
    typeof value.expiresAt === "string"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
