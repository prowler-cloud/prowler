"use server";

import { apiBaseUrl } from "@/lib";
import { getAuthHeaders } from "@/lib/auth-headers";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const RECIPIENTS_PATH = "/alerts/recipients";

export const listAlertRecipients = async (
  searchParams?: Record<string, string | undefined>,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${RECIPIENTS_PATH}`);

  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && value !== "") {
        url.searchParams.append(key, value);
      }
    }
  }

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
