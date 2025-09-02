"use server";

import {
  apiBaseUrl,
  getAuthHeaders,
  handleApiError,
  handleApiResponse,
} from "@/lib";

export const getTask = async (taskId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/tasks/${taskId}`);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
