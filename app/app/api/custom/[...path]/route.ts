import { NextResponse } from "next/server";
import { getServerToken } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

const REQUEST_TIMEOUT_MS = 15_000;
const CLIENT_CLOSED_REQUEST = 499;

async function proxyCustomEndpoint(
  request: Request,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const token = await getServerToken();
  if (!token) {
    return NextResponse.json(
      { errors: [{ message: "missing authentication" }] },
      { status: 401 },
    );
  }

  const { path } = await params;
  const source = new URL(request.url);
  const backend = new URL(getGraphqlEndpoint());
  backend.pathname = `/api/custom/${path.join("/")}`;
  backend.search = source.search;

  let response: Response;
  try {
    response = await fetch(backend, {
      method: request.method,
      headers: withForwardedClientIpHeaders(request, {
        accept: request.headers.get("accept") ?? "application/json",
        authorization: `Bearer ${token}`,
        "content-type":
          request.headers.get("content-type") ?? "application/json",
      }),
      body: request.method === "GET" ? undefined : request.body,
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
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
    },
  });
}

export const GET = proxyCustomEndpoint;
export const POST = proxyCustomEndpoint;
export const PUT = proxyCustomEndpoint;
export const PATCH = proxyCustomEndpoint;
export const DELETE = proxyCustomEndpoint;

function isRequestAbort(error: unknown) {
  if (!(error instanceof Error || error instanceof DOMException)) {
    return false;
  }
  return ["AbortError", "TimeoutError", "ResponseAborted"].includes(error.name);
}
