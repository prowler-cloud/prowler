"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { ScheduleUpdatePayload } from "@/types/schedules";

function revalidateScheduleViews() {
  revalidatePath("/scans");
  revalidatePath("/providers");
}

export const getSchedule = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);
  url.searchParams.set("include", "provider");

  try {
    const response = await fetch(url.toString(), { headers });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateSchedule = async (
  providerId: string,
  payload: ScheduleUpdatePayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "schedules",
          id: providerId,
          attributes: payload,
        },
      }),
    });

    const result = await handleApiResponse(response);
    if (!result?.error) {
      revalidateScheduleViews();
    }
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const removeSchedule = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    const result = await handleApiResponse(response);
    if (!result?.error) {
      revalidateScheduleViews();
    }
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};
