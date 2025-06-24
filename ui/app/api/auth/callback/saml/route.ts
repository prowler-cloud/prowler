"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";
import { baseUrl } from "@/lib/helper";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  console.log("SAML Callback - Search params:", searchParams);
  console.log("SAML Callback - Full URL:", req.url);

  const access = searchParams.get("access");
  const refresh = searchParams.get("refresh");

  if (!access || !refresh) {
    return NextResponse.json(
      { error: "Access token or refresh token is missing" },
      { status: 400 },
    );
  }

  try {
    const result = await signIn("social-oauth", {
      accessToken: access,
      refreshToken: refresh,
      redirect: false,
      callbackUrl: `${baseUrl}/`,
    });

    if (result?.error) {
      throw new Error(result.error);
    }

    return NextResponse.redirect(new URL("/", baseUrl));
  } catch (error) {
    console.error("SAML authentication failed:", error);
    return NextResponse.redirect(
      new URL("/sign-in?error=SAMLAuthenticationFailed", baseUrl),
    );
  }
}
