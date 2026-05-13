import { NextResponse } from "next/server";
import { AUTH_COOKIE, AUTH_META_COOKIE } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";

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
    headers: { "content-type": "application/json" },
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
  const secure = process.env.NODE_ENV === "production";
  const res = NextResponse.json({
    entityId: login.entityId,
    sessionId: login.sessionId,
    expiresAt: login.expiresAt,
  });

  res.cookies.set(AUTH_COOKIE, login.token, {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    expires: new Date(login.expiresAt),
  });
  res.cookies.set(
    AUTH_META_COOKIE,
    JSON.stringify({
      entityId: login.entityId,
      sessionId: login.sessionId,
      expiresAt: login.expiresAt,
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      expires: new Date(login.expiresAt),
    },
  );

  return res;
}
