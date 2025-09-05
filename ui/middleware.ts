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

export default auth((req: NextRequest & { auth: any }) => {
  const { pathname } = req.nextUrl;
  const user = req.auth?.user;

  if (!user && !isPublicRoute(pathname)) {
    return NextResponse.redirect(new URL("/sign-in", req.url));
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
