import { NextResponse } from "next/server";
import type { NextAuthRequest } from "next-auth";

import { auth } from "@/auth.config";

const guestOnlyRoutes = ["/sign-in", "/sign-up"];
const CLOUD_ATTRIBUTION_PARAMS = ["utm_source", "utm_content"] as const;

const publicRoutes = [
  "/sign-in",
  "/sign-up",
  "/invitation/accept",
  // In Cloud uncomment the following lines:
  // "/reset-password",
  // "/email-verification",
  // "/set-password",
];

const isPublicRoute = (pathname: string): boolean => {
  return publicRoutes.some((route) => pathname.startsWith(route));
};

const isGuestOnlyRoute = (pathname: string): boolean =>
  guestOnlyRoutes.includes(pathname);

// NextAuth's auth() wrapper - renamed from middleware to proxy
const handleProxyRequest = (req: NextAuthRequest) => {
  const { pathname } = req.nextUrl;

  const user = req.auth?.user;
  const sessionError = req.auth?.error;

  // If there's a session error (e.g., RefreshAccessTokenError), redirect to login with error info
  if (sessionError && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("error", sessionError);
    signInUrl.searchParams.set("callbackUrl", pathname + req.nextUrl.search);
    return NextResponse.redirect(signInUrl);
  }

  if (!user && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("callbackUrl", pathname + req.nextUrl.search);
    return NextResponse.redirect(signInUrl);
  }

  if (user && isGuestOnlyRoute(pathname)) {
    const dashboardUrl = new URL("/", req.url);

    CLOUD_ATTRIBUTION_PARAMS.forEach((param) => {
      const value = req.nextUrl.searchParams.get(param);
      if (value !== null) {
        dashboardUrl.searchParams.set(param, value);
      }
    });

    return NextResponse.redirect(dashboardUrl);
  }

  if (user?.permissions) {
    const permissions = user.permissions;

    if (pathname.startsWith("/billing") && !permissions.manage_billing) {
      return NextResponse.redirect(new URL("/profile", req.url));
    }

    if (
      pathname.startsWith("/integrations") &&
      !permissions.manage_integrations
    ) {
      return NextResponse.redirect(new URL("/profile", req.url));
    }
  }

  return NextResponse.next();
};

export default auth(handleProxyRequest);

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - *.png, *.jpg, *.jpeg, *.svg, *.ico (image files)
     */
    "/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|svg|ico|css|js)$).*)",
  ],
};
