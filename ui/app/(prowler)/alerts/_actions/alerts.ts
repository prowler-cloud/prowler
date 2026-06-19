"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

import {
  ALERT_SCHEMA_VERSION,
  type AlertCondition,
  type AlertTriggerKind,
} from "../_types";

const ALERT_RULES_API_PATH = "/alerts/rules";
const ALERTS_REVALIDATE_PATH = "/alerts";

export interface AlertPayload {
  name: string;
  description?: string;
  enabled?: boolean;
  trigger: AlertTriggerKind;
  condition: AlertCondition;
  /**
   * List of recipient email addresses. The API resolves them to existing
   * `AlertRecipient` rows or creates new pending ones with confirmation
   * emails. Recipient IDs are NOT used by the rule write path.
   */
  recipientEmails?: string[];
}

const buildRuleEnvelope = (payload: AlertPayload, alertId?: string) => ({
  data: {
    type: "alert-rules",
    ...(alertId ? { id: alertId } : {}),
    attributes: {
      name: payload.name,
      description: payload.description ?? "",
      enabled: payload.enabled ?? true,
      trigger: payload.trigger,
      condition: payload.condition,
      schema_version: ALERT_SCHEMA_VERSION,
      ...(payload.recipientEmails !== undefined
        ? { recipient_emails: payload.recipientEmails }
        : {}),
    },
  },
});

const buildEnabledEnvelope = (alertId: string, enabled: boolean) => ({
  data: {
    type: "alert-rules",
    id: alertId,
    attributes: { enabled },
  },
});

const buildSeedEnvelope = (filterBag: Record<string, string | string[]>) => ({
  data: {
    type: "alert-rule-seedings",
    attributes: { filter_bag: filterBag },
  },
});

export const listAlerts = async (
  searchParams?: Record<string, string | undefined>,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}`);

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

export const getAlert = async (alertId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/${alertId}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const seedAlertRule = async (
  filterBag: Record<string, string | string[]>,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/seed`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(buildSeedEnvelope(filterBag)),
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const createAlert = async (payload: AlertPayload) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(buildRuleEnvelope(payload)),
    });
    return handleApiResponse(response, ALERTS_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateAlert = async (alertId: string, payload: AlertPayload) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/${alertId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(buildRuleEnvelope(payload, alertId)),
    });
    return handleApiResponse(response, ALERTS_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteAlert = async (alertId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/${alertId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    return handleApiResponse(response, ALERTS_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

export const enableAlert = async (alertId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/${alertId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(buildEnabledEnvelope(alertId, true)),
    });
    return handleApiResponse(response, ALERTS_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

export const disableAlert = async (alertId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/${alertId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(buildEnabledEnvelope(alertId, false)),
    });
    return handleApiResponse(response, ALERTS_REVALIDATE_PATH);
  } catch (error) {
    return handleApiError(error);
  }
};

export const previewAlertCondition = async (payload: {
  condition: AlertCondition;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${ALERT_RULES_API_PATH}/preview`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "alert-rule-previews",
          attributes: { condition: payload.condition },
        },
      }),
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
