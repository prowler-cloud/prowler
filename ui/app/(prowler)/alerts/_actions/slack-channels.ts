"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const ALERT_SLACK_CHANNELS_PATH = "/alerts/slack-channels";
const CHANNELS_PAGE_SIZE = "100";

/**
 * The channels eligible as alert destinations, from the tenant's enabled and
 * connected Slack integration. Server-side only: no Slack round-trip, so no
 * cursor pagination. The page size is still sent because the API paginates
 * collections by default and the picker reads `data` flat, so a default page
 * would truncate the pool silently.
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
