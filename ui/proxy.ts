import { NextFetchEvent, NextResponse } from "next/server";
import type { NextAuthRequest } from "next-auth";

import { auth } from "@/auth.config";
import { apiBaseUrl } from "@/lib";
import { fetchMaintenanceStatus, maintenanceResponse } from "@/lib/maintenance";
import { isCloud } from "@/lib/shared/env";

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

// NextAuth's auth() wrapper - renamed from middleware to proxy.
//
// Maintenance Mode (MM) is a Cloud-only feature (see `lib/maintenance.ts`).
// Its gate runs from the exported `proxy()` wrapper below, guarded by
// `isCloud()`, so self-hosted deployments never issue the status fetch and
// this handler behaves exactly as it did before MM existed.
const authProxy = auth((req: NextAuthRequest) => {
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
});

export default async function proxy(
  req: NextAuthRequest,
  ctx: NextFetchEvent,
): Promise<NextResponse> {
  // Maintenance Mode is Cloud-only: self-hosted has no MM status endpoint,
  // so skip the fetch entirely rather than issue it on every request only to
  // fail open. Fail-open contract for the Cloud path itself: any error
  // fetching the status is treated as MM off (never lock users out on a
  // status blip). When MM is on, every matched request is rewritten to the
  // dependency-free /maintenance landing page; when MM is off, /maintenance
  // redirects back to /.
  if (isCloud()) {
    const status = await fetchMaintenanceStatus(apiBaseUrl);
    const gate = maintenanceResponse(req, status);
    if (gate) {
      return gate;
    }
  }

  // Delegate to the NextAuth-wrapped handler for normal auth/permission flow.
  // Next passes a NextFetchEvent as the middleware context; next-auth's
  // `auth()` wrapper types the param as AppRouteHandlerFnContext, so bridge it.
  return (await authProxy(
    req,
    ctx as unknown as Parameters<typeof authProxy>[1],
  )) as NextResponse;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - *.png, *.jpg, *.jpeg, *.svg, *.ico (image files)
     *
     * /maintenance IS matched (not excluded): when the Cloud MM gate is
     * active it must run there too so its terminal branch (MM on + already
     * on /maintenance) can return NextResponse.next() itself instead of
     * falling through to authProxy, which would redirect an unauthenticated
     * visitor to /sign-in. Self-hosted never reaches that branch (gated by
     * isCloud() above), but the route stays unexcluded either way.
     */
    "/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|svg|ico|css|js)$).*)",
  ],
};
