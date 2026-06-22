"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { ScheduleProps, ScheduleUpdatePayload } from "@/types/schedules";

// SSRF guard: the id is interpolated into the request URL, so only UUIDs pass.
const providerIdSchema = z.uuid();

function parseProviderId(providerId: string): string | null {
  const parsed = providerIdSchema.safeParse(providerId);
  return parsed.success ? parsed.data : null;
}

function revalidateScheduleViews() {
  revalidatePath("/scans");
  revalidatePath("/providers");
}

export const getSchedule = async (providerId: string) => {
  const id = parseProviderId(providerId);
  if (!id) return { error: "Invalid provider id." };

  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/schedules/${id}`);
  url.searchParams.set("include", "provider");

  try {
    const response = await fetch(url.toString(), { headers });

    return handleApiResponse(response);
  } catch (error) {
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

      const response = await fetch(url.toString(), { headers });

      const result = await handleApiResponse(response);
      if (result?.error) return result;

      schedules.push(...(result?.data ?? []));

      const totalPages = result?.meta?.pagination?.pages ?? 1;
      if (page >= totalPages) break;
    }

    return { data: schedules };
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateSchedule = async (
  providerId: string,
  payload: ScheduleUpdatePayload,
) => {
  const id = parseProviderId(providerId);
  if (!id) return { error: "Invalid provider id." };

  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${id}`);

  const body = {
    data: {
      type: "schedules",
      id,
      attributes: payload,
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
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
  const id = parseProviderId(providerId);
  if (!id) return { error: "Invalid provider id." };

  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/schedules/${id}`);

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
