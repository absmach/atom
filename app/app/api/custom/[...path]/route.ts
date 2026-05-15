import { NextResponse } from "next/server";
import { getServerToken } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";

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

  const response = await fetch(backend, {
    method: request.method,
    headers: {
      accept: request.headers.get("accept") ?? "application/json",
      authorization: `Bearer ${token}`,
      "content-type": request.headers.get("content-type") ?? "application/json",
    },
    body: request.method === "GET" ? undefined : await request.text(),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
  });

  return new NextResponse(await response.text(), {
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
