import { NextResponse } from "next/server";
import { isUiRegistrationEnabled } from "@/lib/auth/registration";
import { getBackendBaseUrl } from "@/lib/graphql/client";
import { withForwardedClientIpHeaders } from "@/lib/http/client-ip-headers";

export async function POST(request: Request) {
  if (!isUiRegistrationEnabled()) {
    return NextResponse.json(
      { message: "Registration is disabled" },
      { status: 403 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ message: "Invalid JSON body" }, { status: 400 });
  }

  const response = await fetch(`${getBackendBaseUrl()}/auth/signup`, {
    method: "POST",
    headers: withForwardedClientIpHeaders(request, {
      "content-type": "application/json",
    }),
    body: JSON.stringify(body),
    cache: "no-store",
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    return NextResponse.json(
      {
        message: payload.error ?? payload.message ?? "Unable to create account",
      },
      { status: response.status },
    );
  }

  return NextResponse.json(payload, { status: response.status });
}
