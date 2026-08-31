import { NextResponse } from "next/server";
import { setAuthCookies } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

const LOGIN_MUTATION = `
mutation Login($input: LoginInput!) {
  login(input: $input) {
    token
    entityId
    sessionId
    expiresAt
  }
}
`;

export async function POST(request: Request) {
  const body = await request.json();
  const response = await fetch(getGraphqlEndpoint(), {
    method: "POST",
    headers: withForwardedClientIpHeaders(request, {
      "content-type": "application/json",
    }),
    body: JSON.stringify({
      query: LOGIN_MUTATION,
      variables: {
        input: {
          identifier: body.identifier,
          secret: body.secret,
          kind: "password",
        },
      },
      operationName: "Login",
    }),
  });

  const payload = await response.json();
  if (!response.ok || payload.errors?.length) {
    return NextResponse.json(
      { message: payload.errors?.[0]?.message ?? "Login failed" },
      { status: 401 },
    );
  }

  const login = payload.data.login;
  const res = NextResponse.json({
    entityId: login.entityId,
    sessionId: login.sessionId,
    expiresAt: login.expiresAt,
  });
  setAuthCookies(res, login);

  return res;
}
