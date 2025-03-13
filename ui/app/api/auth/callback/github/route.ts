"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);

  const keyServer = process.env.API_BASE_URL;

  const code = searchParams.get("code");

  const params = new URLSearchParams();
  params.append("code", code || "");

  if (!code) {
    return NextResponse.json(
      { error: "Authorization code is missing" },
      { status: 400 },
    );
  }

  try {
    const response = await fetch(`${keyServer}/tokens/github`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error("Failed to exchange code for tokens");
    }

    const data = await response.json();
    const { access, refresh } = data.data.attributes;

    try {
      const result = await signIn("social-oauth", {
        accessToken: access,
        refreshToken: refresh,
        redirect: false,
        callbackUrl: "/",
      });

      if (result?.error) {
        throw new Error(result.error);
      }

      return NextResponse.redirect(new URL("/", req.url));
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error("SignIn error:", error);
      return NextResponse.redirect(
        new URL("/sign-in?error=AuthenticationFailed", req.url),
      );
    }
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error in Github callback:", error);
    return NextResponse.json(
      { error: (error as Error).message },
      { status: 500 },
    );
  }
}
