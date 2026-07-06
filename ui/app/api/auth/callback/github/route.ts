"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";
import {
  getInvitationTokenFromCallbackPath,
  getSafeCallbackPath,
} from "@/lib/auth-callback-url";
import { apiBaseUrl, baseUrl } from "@/lib/helper";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);

  const code = searchParams.get("code");
  const callbackPath = getSafeCallbackPath(searchParams);
  const invitationToken = getInvitationTokenFromCallbackPath(callbackPath);

  const params = new URLSearchParams();
  params.append("code", code || "");
  if (invitationToken) {
    params.append("invitation_token", invitationToken);
  }

  if (!code) {
    return NextResponse.json(
      { error: "Authorization code is missing" },
      { status: 400 },
    );
  }

  try {
    const response = await fetch(`${apiBaseUrl}/tokens/github`, {
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
      // Invitation tokens are accepted during the social token exchange.
      const redirectPath = invitationToken ? "/" : callbackPath;
      const result = await signIn("social-oauth", {
        accessToken: access,
        refreshToken: refresh,
        redirect: false,
        callbackUrl: new URL(redirectPath, baseUrl).toString(),
      });

      if (result?.error) {
        throw new Error(result.error);
      }

      return NextResponse.redirect(new URL(redirectPath, baseUrl));
    } catch (error) {
      console.error("SignIn error:", error);
      return NextResponse.redirect(
        new URL("/sign-in?error=AuthenticationFailed", baseUrl),
      );
    }
  } catch (error) {
    console.error("Error in Github callback:", error);
    return NextResponse.redirect(
      new URL("/sign-in?error=AuthenticationFailed", baseUrl),
    );
  }
}
