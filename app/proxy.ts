import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { AUTH_COOKIE, AUTH_META_COOKIE } from "@/lib/auth/constants";

const REDIRECT_TO_LOGIN = new Set(["/verify-email", "/callback"]);
const PUBLIC_PAGES = new Set(["/login", "/register"]);
const REAUTH_PARAM = "reauth";

function isFreshSessionMeta(raw: string | undefined) {
  if (!raw) return false;

  try {
    const parsed = JSON.parse(raw) as { expiresAt?: unknown };
    if (typeof parsed.expiresAt !== "string") return false;

    const expiresAt = Date.parse(parsed.expiresAt);
    return !Number.isNaN(expiresAt) && expiresAt > Date.now();
  } catch {
    return false;
  }
}

function authState(request: NextRequest) {
  const token = request.cookies.get(AUTH_COOKIE)?.value;
  const session = request.cookies.get(AUTH_META_COOKIE)?.value;
  const valid = Boolean(token && isFreshSessionMeta(session));

  return {
    valid,
    stale: Boolean((token || session) && !valid),
  };
}

function clearAuthCookies(response: NextResponse) {
  response.cookies.delete(AUTH_COOKIE);
  response.cookies.delete(AUTH_META_COOKIE);
  return response;
}

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const auth = authState(request);
  const reauth = request.nextUrl.searchParams.has(REAUTH_PARAM);

  if (REDIRECT_TO_LOGIN.has(pathname)) {
    return clearAuthCookies(
      NextResponse.redirect(new URL(`/login?${REAUTH_PARAM}=1`, request.url)),
    );
  }

  if (PUBLIC_PAGES.has(pathname) && auth.valid && !reauth) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  if (PUBLIC_PAGES.has(pathname)) {
    const response = NextResponse.next();
    return auth.stale || reauth ? clearAuthCookies(response) : response;
  }

  if (!auth.valid) {
    const url = new URL("/login", request.url);
    url.searchParams.set("next", pathname);
    const response = NextResponse.redirect(url);
    return auth.stale ? clearAuthCookies(response) : response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next|favicon.ico|.*\\..*).*)"],
};
