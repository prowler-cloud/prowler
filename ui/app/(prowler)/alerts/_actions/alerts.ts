"use server";

import * as Sentry from "@sentry/nextjs";
import { revalidatePath } from "next/cache";

import {
  ALERT_ERROR_CODES,
  ALERT_SCHEMA_VERSION,
  type AlertCondition,
  type AlertPreviewResponse,
  type AlertRule,
  type AlertsActionResult,
  type AlertSeedWarning,
  type AlertTriggerKind,
} from "../_types";
import { alertsRequest } from "./_request";

const ALERT_RULES_API_PATH = "/alerts/rules";
const ALERTS_BASE_PATH = "/alerts";

const revalidateAlertsBase = () => {
  revalidatePath(ALERTS_BASE_PATH);
};

const revalidateAlert = (alertId: string) => {
  revalidatePath(`${ALERTS_BASE_PATH}/${alertId}`);
};

const breadcrumb = (
  category: string,
  message: string,
  data?: Record<string, unknown>,
) => {
  Sentry.addBreadcrumb({ category, message, level: "info", data });
};

export interface AlertsListResponse {
  data: AlertRule[];
  meta?: {
    pagination?: { count: number; pages: number; page: number };
  };
}

export interface AlertSeedResult {
  condition: AlertCondition;
  schemaVersion: number;
  warnings: AlertSeedWarning[];
}

interface AlertSeedEnvelope {
  data?: {
    id?: string;
    type?: "alert-rule-seedings";
    attributes?: {
      condition?: AlertCondition;
      schema_version?: number;
      warnings?: AlertSeedWarning[];
    };
  };
}

const buildSeedEnvelope = (filterBag: Record<string, string | string[]>) => ({
  data: {
    type: "alert-rule-seedings",
    attributes: {
      filter_bag: filterBag,
    },
  },
});

const normalizeSeedResponse = (value: AlertSeedEnvelope): AlertSeedResult => {
  const attributes = value.data?.attributes;
  if (!attributes?.condition) {
    throw new Error("Seed response is missing condition.");
  }

  return {
    condition: attributes.condition,
    schemaVersion: attributes.schema_version ?? ALERT_SCHEMA_VERSION,
    warnings: attributes.warnings ?? [],
  };
};

export const listAlerts = async (
  searchParams?: URLSearchParams,
): Promise<AlertsActionResult<AlertsListResponse>> =>
  alertsRequest<AlertsListResponse>(ALERT_RULES_API_PATH, {
    method: "GET",
    query: searchParams,
  });

export const getAlert = async (
  alertId: string,
): Promise<AlertsActionResult<{ data: AlertRule }>> =>
  alertsRequest<{ data: AlertRule }>(`${ALERT_RULES_API_PATH}/${alertId}`, {
    method: "GET",
  });

export const seedAlertRule = async (
  filterBag: Record<string, string | string[]>,
): Promise<AlertsActionResult<AlertSeedResult>> => {
  const result = await alertsRequest<AlertSeedEnvelope>(
    `${ALERT_RULES_API_PATH}/seed`,
    {
      method: "POST",
      body: buildSeedEnvelope(filterBag),
    },
  );

  breadcrumb(
    result.ok ? "alerts.seed" : "alerts.seed.failed",
    "Seeded alert condition",
    { ok: result.ok },
  );

  if (!result.ok) return result;

  try {
    return { ...result, data: normalizeSeedResponse(result.data) };
  } catch (error) {
    Sentry.captureException(error, {
      tags: { error_source: "alerts.seed" },
      level: "error",
    });
    return {
      ok: false,
      error: {
        code: ALERT_ERROR_CODES.UNKNOWN,
        detail:
          error instanceof Error ? error.message : "Seed response is invalid.",
      },
    };
  }
};

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

export const createAlert = async (
  payload: AlertPayload,
): Promise<AlertsActionResult<{ data: AlertRule }>> => {
  const result = await alertsRequest<{ data: AlertRule }>(
    ALERT_RULES_API_PATH,
    {
      method: "POST",
      body: buildRuleEnvelope(payload),
    },
  );
  if (result.ok) {
    breadcrumb("alerts.create", "Created alert", {
      alertId: result.data?.data?.id,
    });
    revalidateAlertsBase();
  }
  return result;
};

export const updateAlert = async (
  alertId: string,
  payload: AlertPayload,
): Promise<AlertsActionResult<{ data: AlertRule }>> => {
  const result = await alertsRequest<{ data: AlertRule }>(
    `${ALERT_RULES_API_PATH}/${alertId}`,
    {
      method: "PATCH",
      body: buildRuleEnvelope(payload, alertId),
    },
  );
  if (result.ok) {
    breadcrumb("alerts.update", "Updated alert", { alertId });
    revalidateAlertsBase();
    revalidateAlert(alertId);
  }
  return result;
};

export const deleteAlert = async (
  alertId: string,
): Promise<AlertsActionResult<undefined>> => {
  const result = await alertsRequest<undefined>(
    `${ALERT_RULES_API_PATH}/${alertId}`,
    {
      method: "DELETE",
    },
  );
  if (result.ok) {
    breadcrumb("alerts.delete", "Deleted alert", { alertId });
    revalidateAlertsBase();
  }
  return result;
};

export const enableAlert = async (
  alertId: string,
): Promise<AlertsActionResult<{ data: AlertRule }>> => {
  const result = await alertsRequest<{ data: AlertRule }>(
    `${ALERT_RULES_API_PATH}/${alertId}`,
    {
      method: "PATCH",
      body: buildEnabledEnvelope(alertId, true),
    },
  );
  if (result.ok) {
    breadcrumb("alerts.enable", "Enabled alert", { alertId });
    revalidateAlertsBase();
    revalidateAlert(alertId);
  }
  return result;
};

export const disableAlert = async (
  alertId: string,
): Promise<AlertsActionResult<{ data: AlertRule }>> => {
  const result = await alertsRequest<{ data: AlertRule }>(
    `${ALERT_RULES_API_PATH}/${alertId}`,
    {
      method: "PATCH",
      body: buildEnabledEnvelope(alertId, false),
    },
  );
  if (result.ok) {
    breadcrumb("alerts.disable", "Disabled alert", { alertId });
    revalidateAlertsBase();
    revalidateAlert(alertId);
  }
  return result;
};

interface AlertPreviewEnvelope {
  data?: {
    type?: "alert-rule-previews";
    id?: string;
    attributes?: Partial<AlertPreviewResponse>;
  };
  meta?: Record<string, unknown>;
}

const isAlertPreviewEnvelope = (
  value: AlertPreviewResponse | AlertPreviewEnvelope,
): value is AlertPreviewEnvelope =>
  "data" in value &&
  typeof value.data === "object" &&
  value.data !== null &&
  "attributes" in value.data;

const normalizePreviewResponse = (
  value: AlertPreviewResponse | AlertPreviewEnvelope,
): AlertPreviewResponse => {
  const attributes = isAlertPreviewEnvelope(value)
    ? value.data?.attributes
    : value;

  if (!attributes) {
    return {
      would_fire: false,
      summary: { finding_count_total: 0 },
      sample_finding_ids: [],
      evaluation_failed: true,
      last_error: "Preview response is missing attributes.",
    };
  }

  const summary = attributes.summary ?? { finding_count_total: 0 };

  return {
    would_fire: attributes.would_fire ?? false,
    summary,
    sample_finding_ids:
      attributes.sample_finding_ids ?? summary.top_findings ?? [],
    evaluation_failed: attributes.evaluation_failed ?? false,
    last_error: attributes.last_error,
    summary_fallback: attributes.summary_fallback,
    duration_ms: attributes.duration_ms,
  };
};

export const previewAlertCondition = async (payload: {
  condition: AlertCondition;
}): Promise<AlertsActionResult<AlertPreviewResponse>> => {
  const result = await alertsRequest<
    AlertPreviewResponse | AlertPreviewEnvelope
  >(`${ALERT_RULES_API_PATH}/preview`, {
    method: "POST",
    body: {
      data: {
        type: "alert-rule-previews",
        attributes: {
          condition: payload.condition,
        },
      },
    },
  });
  breadcrumb(
    result.ok ? "alerts.preview" : "alerts.preview.failed",
    "Previewed alert condition",
    { ok: result.ok },
  );
  if (!result.ok) return result;
  return { ...result, data: normalizePreviewResponse(result.data) };
};
