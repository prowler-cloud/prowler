import { NextRequest, NextResponse } from "next/server";

import { auth } from "@/auth.config";

const publicRoutes = [
  "/sign-in",
  "/sign-up",
  // In Cloud uncomment the following lines:
  // "/reset-password",
  // "/email-verification",
  // "/set-password",
];

const isPublicRoute = (pathname: string): boolean => {
  return publicRoutes.some((route) => pathname.startsWith(route));
};

// NextAuth's auth() wrapper - renamed from middleware to proxy
export default auth((req: NextRequest & { auth: any }) => {
  const { pathname } = req.nextUrl;
  const user = req.auth?.user;
  const sessionError = req.auth?.error;

  // If there's a session error (e.g., RefreshAccessTokenError), redirect to login with error info
  if (sessionError && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("error", sessionError);
    signInUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(signInUrl);
  }

  if (!user && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(signInUrl);
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

  // Redirect /findings to include default muted filter if not present
  if (
    pathname === "/findings" &&
    !req.nextUrl.searchParams.has("filter[muted]")
  ) {
    const findingsUrl = new URL("/findings", req.url);
    // Preserve existing search params
    req.nextUrl.searchParams.forEach((value, key) => {
      findingsUrl.searchParams.set(key, value);
    });
    findingsUrl.searchParams.set("filter[muted]", "false");
    return NextResponse.redirect(findingsUrl);
  }

  return NextResponse.next();
});

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
