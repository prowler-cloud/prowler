"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const ALERT_SLACK_CHANNELS_PATH = "/alerts/slack-channels";

/**
 * The channels eligible as alert destinations, from the tenant's enabled and
 * connected Slack integration. Server-side only: no Slack round-trip, so the
 * alert form has neither pagination nor a listing-failure state.
 */
export const getAlertSlackChannels = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ALERT_SLACK_CHANNELS_PATH}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
