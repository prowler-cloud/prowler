"use server";

import { NextResponse } from "next/server";

import { signIn } from "@/auth.config";
import { baseUrl } from "@/lib/helper";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const id = searchParams.get("id");

  if (!id) {
    return NextResponse.json(
      { error: "ID parameter is missing" },
      { status: 400 },
    );
  }

  // Use API_BASE_URL (runtime env var) rather than NEXT_PUBLIC_API_BASE_URL
  // which is baked into the bundle at build time and may contain the Docker
  // Compose hostname (prowler-api) instead of the deployed public URL.
  const apiBaseUrl =
    process.env.API_BASE_URL || process.env.NEXT_PUBLIC_API_BASE_URL;

  try {
    const response = await fetch(`${apiBaseUrl}/tokens/saml?id=${id}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch tokens: ${response.statusText}`);
    }

    const tokenData = await response.json();
    const { access, refresh } = tokenData.data;

    if (!access || !refresh) {
      throw new Error("Tokens not found in response");
    }

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
    return NextResponse.redirect(new URL("/sign-in", baseUrl));
  }
}
