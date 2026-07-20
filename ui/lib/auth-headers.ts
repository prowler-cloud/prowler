import "server-only";

import { auth } from "@/auth.config";

import { getRequiredAuthHeaders } from "./server-auth";

export const getAuthHeaders = async (options?: { contentType?: boolean }) => {
  const session = await auth();

  return getRequiredAuthHeaders(session?.accessToken, options, session?.error);
};
