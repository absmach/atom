import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { AUTH_COOKIE } from "@/lib/auth/constants";

const REDIRECT_TO_LOGIN = new Set(["/register", "/verify-email", "/callback"]);
const PUBLIC_PAGES = new Set(["/login"]);

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (REDIRECT_TO_LOGIN.has(pathname)) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  const token = request.cookies.get(AUTH_COOKIE)?.value;

  if (PUBLIC_PAGES.has(pathname) && token) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  if (!PUBLIC_PAGES.has(pathname) && !token) {
    const url = new URL("/login", request.url);
    url.searchParams.set("next", pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next|favicon.ico|.*\\..*).*)"],
};
