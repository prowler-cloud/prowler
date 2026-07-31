import "server-only";

import { auth } from "@/auth.config";

import {
  getAuthHeadersIfAvailable,
  getRequiredAuthHeaders,
} from "./server-auth";

export const getAuthHeaders = async (options?: { contentType?: boolean }) => {
  const session = await auth();

  return getRequiredAuthHeaders(session?.accessToken, options, session?.error);
};

export const getRouteAuthHeaders = async (options?: {
  contentType?: boolean;
}) => {
  const session = await auth();

  return getAuthHeadersIfAvailable(
    session?.accessToken,
    options,
    session?.error,
  );
};
