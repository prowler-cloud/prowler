import { NextResponse } from "next/server";
import type { NextAuthRequest } from "next-auth";

import { auth } from "@/auth.config";
import { getCspHeader } from "@/lib/csp";
import {
  GATED_INTEGRATIONS,
  isGatedIntegrationEnabled,
  readGatedEnv,
} from "@/lib/integrations";
import { readEnv } from "@/lib/runtime-env";
import { isCloud } from "@/lib/shared/env";
import { copyAttributionParams } from "@/lib/utm";

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

const withSecurityHeaders = (response: NextResponse): NextResponse => {
  response.headers.set(
    "Content-Security-Policy",
    getCspHeader({
      cloudEnabled: isCloud(),
      posthogEnabled: isGatedIntegrationEnabled(GATED_INTEGRATIONS.posthog),
      posthogKey: readGatedEnv(
        "UI_POSTHOG_ENABLED",
        "UI_POSTHOG_KEY",
        "POSTHOG_KEY",
      ),
      posthogHost: readGatedEnv(
        "UI_POSTHOG_ENABLED",
        "UI_POSTHOG_HOST",
        "POSTHOG_HOST",
      ),
    }),
  );
  return response;
};

const redirect = (url: URL): NextResponse =>
  withSecurityHeaders(NextResponse.redirect(url));

// NextAuth's auth() wrapper - renamed from middleware to proxy
export default auth((req: NextAuthRequest) => {
  const { pathname } = req.nextUrl;

  const user = req.auth?.user;
  const sessionError = req.auth?.error;
  const cloudBillingEnabled =
    (readEnv("CLOUD_BILLING_ENABLED") ?? "false") !== "false";

  // If there's a session error (e.g., RefreshAccessTokenError), redirect to login with error info
  if (sessionError && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("error", sessionError);
    signInUrl.searchParams.set("callbackUrl", pathname + req.nextUrl.search);
    copyAttributionParams(req.nextUrl.searchParams, signInUrl.searchParams);
    return redirect(signInUrl);
  }

  if (!user && !isPublicRoute(pathname)) {
    const signInUrl = new URL("/sign-in", req.url);
    signInUrl.searchParams.set("callbackUrl", pathname + req.nextUrl.search);
    copyAttributionParams(req.nextUrl.searchParams, signInUrl.searchParams);
    return redirect(signInUrl);
  }

  if (
    pathname.startsWith("/billing") &&
    (!isCloud() ||
      !cloudBillingEnabled ||
      user?.permissions?.manage_billing !== true)
  ) {
    return redirect(new URL("/profile", req.url));
  }

  if (user?.permissions) {
    const permissions = user.permissions;

    if (
      pathname.startsWith("/integrations") &&
      !permissions.manage_integrations
    ) {
      return redirect(new URL("/profile", req.url));
    }
  }

  return withSecurityHeaders(NextResponse.next());
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
