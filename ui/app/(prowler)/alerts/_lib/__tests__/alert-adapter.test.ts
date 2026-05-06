import { describe, expect, it } from "vitest";

import {
  ALERT_AGGREGATE_OPS,
  ALERT_BOOLEAN_OPS,
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";

import type { AlertFormValues } from "../../_types/alert-form";
import {
  getAlertFormDefaults,
  getFindingsFiltersFromAlertCondition,
  toAlertPayload,
} from "../alert-adapter";

const condition: AlertCondition = {
  op: ALERT_AGGREGATE_OPS.ANY,
  filter: { severity: ["critical", "high"] },
};

const baseValues = {
  name: "  Critical findings  ",
  description: "  Notify security  ",
  method: "email",
  frequency: ALERT_TRIGGER_KINDS.DAILY,
  condition,
  recipientEmails: [" Security@Example.COM ", "ops@example.com"],
  enabled: true,
} satisfies AlertFormValues;

const existingRule = {
  id: "alert-1",
  type: "alert-rules",
  attributes: {
    name: "Existing alert",
    description: "Existing description",
    enabled: false,
    trigger: ALERT_TRIGGER_KINDS.BOTH,
    condition,
    schema_version: 1,
    recipient_emails: ["alerts@example.com"],
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
} satisfies AlertRule;

const countFilter = (filter: Record<string, string[]>) => ({
  op: ALERT_AGGREGATE_OPS.COUNT_GTE,
  filter,
  value: 1,
});

describe("simple alert adapter", () => {
  it("should map form values to the existing create payload contract without translating filters", () => {
    // Given / When
    const payload = toAlertPayload(baseValues);

    // Then
    expect(payload).toEqual({
      name: "Critical findings",
      description: "Notify security",
      enabled: true,
      trigger: ALERT_TRIGGER_KINDS.DAILY,
      condition,
      recipientEmails: ["security@example.com", "ops@example.com"],
    });
    expect(payload.condition).toBe(condition);
    expect(payload).not.toHaveProperty("method");
  });

  it("should hydrate defaults from an existing alert without reshaping the condition", () => {
    // Given / When
    const defaults = getAlertFormDefaults(existingRule);

    // Then
    expect(defaults).toEqual({
      name: "Existing alert",
      description: "Existing description",
      method: "email",
      frequency: ALERT_TRIGGER_KINDS.BOTH,
      condition,
      recipientEmails: ["alerts@example.com"],
      enabled: false,
      advancedCondition: null,
    });
  });

  it("should expose editable alert condition fields as pending Findings filters", () => {
    // Given
    const editableCondition = {
      op: ALERT_BOOLEAN_OPS.AND,
      children: [
        countFilter({ check_id: ["iam_user_no_mfa"] }),
        countFilter({ resource_uid: ["arn:aws:iam::123:user/alice"] }),
        countFilter({ finding_group_id: ["finding-group-1"] }),
        countFilter({ status: ["FAIL"] }),
      ],
    } satisfies AlertCondition;

    // When
    const filters = getFindingsFiltersFromAlertCondition(editableCondition);

    // Then
    expect(filters).toEqual({
      "filter[check_id__in]": ["iam_user_no_mfa"],
      "filter[resource_uid__in]": ["arn:aws:iam::123:user/alice"],
      "filter[finding_group_id]": ["finding-group-1"],
    });
  });
});
