import { NextResponse } from "next/server";
import { getServerToken } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

const REQUEST_TIMEOUT_MS = 15_000;
const CLIENT_CLOSED_REQUEST = 499;

export async function POST(request: Request) {
  const token = await getServerToken();
  if (!token) {
    return NextResponse.json(
      { errors: [{ message: "missing authentication" }] },
      { status: 401 },
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
      body: request.body,
      duplex: "half",
      signal: AbortSignal.any([
        request.signal,
        AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      ]),
    } as RequestInit & { duplex: "half" });
  } catch (error) {
    if (isRequestAbort(error)) {
      return new NextResponse(null, { status: CLIENT_CLOSED_REQUEST });
    }
    throw error;
  }

  return new NextResponse(response.body, {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
}

function isRequestAbort(error: unknown) {
  if (!(error instanceof Error || error instanceof DOMException)) {
    return false;
  }
  return ["AbortError", "TimeoutError", "ResponseAborted"].includes(error.name);
}
