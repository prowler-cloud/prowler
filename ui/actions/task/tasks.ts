"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

export const getTask = async (taskId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    // Must be awaited here, not just returned: ``handleApiResponse`` is
    // itself async and throws on non-2xx — a bare `return` hands back its
    // promise without this function's own `try` ever observing a rejection,
    // so `catch` below never runs and callers get an unhandled rejection
    // instead of the documented `{error}` shape.
    return await handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
