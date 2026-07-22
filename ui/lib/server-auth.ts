import "server-only";

import { headers } from "next/headers";
import { redirect } from "next/navigation";

const CURRENT_PATH_HEADER = "x-prowler-current-path";
const DEFAULT_CALLBACK_PATH = "/";

export const redirectToSignIn = async (): Promise<never> => {
  const requestHeaders = await headers();
  const callbackUrl =
    requestHeaders.get(CURRENT_PATH_HEADER) ?? DEFAULT_CALLBACK_PATH;
  const searchParams = new URLSearchParams({ callbackUrl });

  redirect(`/sign-in?${searchParams.toString()}`);
};

export const getRequiredAuthHeaders = async (
  accessToken: string | undefined,
  options?: { contentType?: boolean },
  sessionError?: string,
) => {
  if (!accessToken || sessionError === "RefreshAccessTokenError") {
    return redirectToSignIn();
  }

  const authHeaders: Record<string, string> = {
    Accept: "application/vnd.api+json",
    Authorization: `Bearer ${accessToken}`,
  };

  if (options?.contentType) {
    authHeaders["Content-Type"] = "application/vnd.api+json";
  }

  return authHeaders;
};
