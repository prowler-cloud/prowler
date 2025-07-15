import { NextRequest, NextResponse } from "next/server";

import { auth } from "@/auth.config";

export default auth((req: NextRequest & { auth: any }) => {
  const { pathname } = req.nextUrl;
  const user = req.auth?.user;

  if (!user && pathname.startsWith("/prowler")) {
    return NextResponse.redirect(new URL("/sign-in", req.url));
  }

  if (user?.permissions) {
    const permissions = user.permissions;

    if (pathname.startsWith("/billing") && !permissions.manage_billing) {
      return NextResponse.redirect(new URL("/", req.url));
    }
  }

  return NextResponse.next();
});

export const config = {
  // https://nextjs.org/docs/app/building-your-application/routing/middleware#matcher
  matcher: ["/((?!api|_next/static|_next/image|.*\\.png$).*)"],
};
