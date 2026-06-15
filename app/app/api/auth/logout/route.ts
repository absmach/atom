import { NextResponse } from "next/server";
import {
  AUTH_COOKIE,
  AUTH_META_COOKIE,
  getServerToken,
} from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

const LOGOUT_MUTATION = `
mutation Logout {
  logout
}
`;

export async function POST(request: Request) {
  const token = await getServerToken();
  if (token) {
    await fetch(getGraphqlEndpoint(), {
      method: "POST",
      headers: withForwardedClientIpHeaders(request, {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      }),
      body: JSON.stringify({ query: LOGOUT_MUTATION, operationName: "Logout" }),
    }).catch(() => undefined);
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.delete(AUTH_COOKIE);
  res.cookies.delete(AUTH_META_COOKIE);
  return res;
}
