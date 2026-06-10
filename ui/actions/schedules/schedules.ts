"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
// TODO: remove debug logging (and ui/lib/debug-api-log.ts) before merging.
import {
  logApiError,
  logApiRequest,
  logApiResponse,
} from "@/lib/debug-api-log";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { ScheduleProps, ScheduleUpdatePayload } from "@/types/schedules";

function revalidateScheduleViews() {
  revalidatePath("/scans");
  revalidatePath("/providers");
}

export const getSchedule = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);
  url.searchParams.set("include", "provider");

  try {
    logApiRequest("GET", url.toString());
    const response = await fetch(url.toString(), { headers });
    await logApiResponse("GET", url.toString(), response);

    return handleApiResponse(response);
  } catch (error) {
    logApiError("GET", url.toString(), error);
    return handleApiError(error);
  }
};

/**
 * Lists every schedule (one per provider), following pagination — the backend
 * has no multi-provider filter.
 */
export const getSchedules = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const schedules: ScheduleProps[] = [];
  const MAX_PAGES = 20;

  try {
    for (let page = 1; page <= MAX_PAGES; page++) {
      const url = new URL(`${apiBaseUrl}/schedules`);
      url.searchParams.set("page[number]", String(page));
      url.searchParams.set("page[size]", "100");

      logApiRequest("GET", url.toString());
      const response = await fetch(url.toString(), { headers });
      await logApiResponse("GET", url.toString(), response);

      const result = await handleApiResponse(response);
      if (result?.error) return result;

      schedules.push(...(result?.data ?? []));

      const totalPages = result?.meta?.pagination?.pages ?? 1;
      if (page >= totalPages) break;
    }

    return { data: schedules };
  } catch (error) {
    logApiError("GET", `${apiBaseUrl}/schedules`, error);
    return handleApiError(error);
  }
};

export const updateSchedule = async (
  providerId: string,
  payload: ScheduleUpdatePayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);

  const body = {
    data: {
      type: "schedules",
      id: providerId,
      attributes: payload,
    },
  };

  try {
    logApiRequest("PATCH", url.toString(), body);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });
    await logApiResponse("PATCH", url.toString(), response);

    const result = await handleApiResponse(response);
    if (!result?.error) {
      revalidateScheduleViews();
    }
    return result;
  } catch (error) {
    logApiError("PATCH", url.toString(), error);
    return handleApiError(error);
  }
};

export const removeSchedule = async (providerId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${providerId}`);

  try {
    logApiRequest("DELETE", url.toString());
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    await logApiResponse("DELETE", url.toString(), response);

    const result = await handleApiResponse(response);
    if (!result?.error) {
      revalidateScheduleViews();
    }
    return result;
  } catch (error) {
    logApiError("DELETE", url.toString(), error);
    return handleApiError(error);
  }
};
