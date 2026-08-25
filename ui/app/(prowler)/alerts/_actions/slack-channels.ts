"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const ALERT_SLACK_CHANNELS_PATH = "/alerts/slack-channels";
const CHANNELS_PAGE_SIZE = "100";

/**
 * The channels eligible as alert destinations. A page size is sent because the
 * API paginates collections by default and the picker reads `data` flat, so a
 * default page could truncate the pool silently.
 */
export const getAlertSlackChannels = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ALERT_SLACK_CHANNELS_PATH}`);
  url.searchParams.append("page[size]", CHANNELS_PAGE_SIZE);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
