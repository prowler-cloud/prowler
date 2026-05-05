"use server";

import { apiBaseUrl } from "@/lib";

import {
  buildAlertsDisabledPublicResponse,
  isAlertsEnabled,
} from "../_lib/env";
import type { AlertPublicResponse } from "../_types";

// NOT FOR THE MVP: public confirm/unsubscribe endpoints are only needed for
// recipient consent links. MVP tenant recipients are already confirmed.
const PUBLIC_PATH = "/alerts/recipients";

const _call = async (
  endpoint: "confirm" | "unsubscribe",
  token: string,
): Promise<AlertPublicResponse> => {
  if (!isAlertsEnabled()) {
    return buildAlertsDisabledPublicResponse();
  }

  if (!apiBaseUrl) {
    return {
      state: "network_error",
      message: "API base URL is not configured.",
    };
  }
  try {
    const url = `${apiBaseUrl}${PUBLIC_PATH}/${endpoint}?token=${encodeURIComponent(token)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const body = (await response
      .json()
      .catch(() => null)) as AlertPublicResponse | null;
    if (body && typeof body === "object" && "state" in body) {
      return body;
    }
    return {
      state: "network_error",
      message: `Unexpected response from server (HTTP ${response.status}).`,
    };
  } catch (err) {
    return {
      state: "network_error",
      message:
        err instanceof Error ? err.message : "Could not reach the server.",
    };
  }
};

export async function confirmRecipient(
  token: string,
): Promise<AlertPublicResponse> {
  return _call("confirm", token);
}

export async function unsubscribeRecipient(
  token: string,
): Promise<AlertPublicResponse> {
  return _call("unsubscribe", token);
}
