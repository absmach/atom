import { NextResponse } from "next/server";
import { getServerToken } from "@/lib/auth/session";
import { getGraphqlEndpoint } from "@/lib/graphql/client";

export async function POST(request: Request) {
  const token = await getServerToken();
  if (!token) {
    return NextResponse.json(
      { errors: [{ message: "missing authentication" }] },
      { status: 401 },
    );
  }

  const response = await fetch(getGraphqlEndpoint(), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: await request.text(),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
  });

  return new NextResponse(await response.text(), {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
}
