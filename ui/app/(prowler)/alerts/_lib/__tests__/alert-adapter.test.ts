import { describe, expect, it } from "vitest";

import {
  ALERT_AGGREGATE_OPS,
  ALERT_BOOLEAN_OPS,
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertLeafFilter,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";

import type { AlertFormValues } from "../../_types/alert-form";
import {
  buildAlertCondition,
  getAlertFormDefaults,
  getAlertFormDefaultsFromFindingsFilters,
  toAlertPayload,
} from "../alert-adapter";

const baseValues = {
  name: "  Critical findings  ",
  description: "  Notify security  ",
  method: "email",
  frequency: ALERT_TRIGGER_KINDS.DAILY,
  filterGroup: {
    operator: "all",
    children: [
      {
        kind: "filter",
        field: "checkSeverities",
        values: ["critical", "high"],
      },
      { kind: "filter", field: "type", values: ["new"] },
      { kind: "filter", field: "providers", values: ["aws"] },
      { kind: "filter", field: "accounts", values: ["provider-1"] },
      { kind: "filter", field: "checks", values: ["iam_user_no_mfa"] },
      { kind: "filter", field: "regions", values: ["us-east-1"] },
      { kind: "filter", field: "services", values: ["iam"] },
      { kind: "filter", field: "categories", values: ["identity-security"] },
      { kind: "filter", field: "resourceGroups", values: ["prod"] },
      { kind: "filter", field: "resourceTypes", values: ["AWS::IAM::User"] },
      {
        kind: "filter",
        field: "resources",
        values: ["arn:aws:iam::123:user/alice"],
      },
      { kind: "filter", field: "checkStatuses", values: ["FAIL"] },
    ],
  },
  severities: ["critical", "high"],
  deltas: ["new"],
  providerTypes: ["aws"],
  providerIds: ["provider-1"],
  checkIds: ["iam_user_no_mfa"],
  categories: ["identity-security"],
  regions: ["us-east-1"],
  services: ["iam"],
  resourceGroups: ["prod"],
  resourceTypes: ["AWS::IAM::User"],
  recipientEmails: [" Security@Example.COM ", "ops@example.com"],
  enabled: true,
} satisfies AlertFormValues;

const advancedCondition: AlertCondition = {
  op: "not",
  child: { op: ALERT_AGGREGATE_OPS.ANY, filter: { severity: ["critical"] } },
};

const countFilter = (filter: AlertLeafFilter) => ({
  op: ALERT_AGGREGATE_OPS.COUNT_GTE,
  filter,
  value: 1,
});

const existingRule = {
  id: "alert-1",
  type: "alert-rules",
  attributes: {
    name: "Existing alert",
    description: "Existing description",
    enabled: false,
    trigger: ALERT_TRIGGER_KINDS.BOTH,
    condition: {
      op: ALERT_AGGREGATE_OPS.ANY,
      filter: { severity: ["medium", "low"] },
    },
    schema_version: 1,
    recipient_emails: ["alerts@example.com"],
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
} satisfies AlertRule;

describe("simple alert adapter", () => {
  describe("payload mapping", () => {
    it("should map simple form values to the existing create payload contract", () => {
      // Given / When
      const payload = toAlertPayload(baseValues);

      // Then
      expect(payload).toEqual({
        name: "Critical findings",
        description: "Notify security",
        enabled: true,
        trigger: ALERT_TRIGGER_KINDS.DAILY,
        condition: {
          op: ALERT_BOOLEAN_OPS.AND,
          children: [
            countFilter({ severity: ["critical", "high"] }),
            countFilter({ delta: ["new"] }),
            countFilter({ provider_type: ["aws"] }),
            countFilter({ provider_id: ["provider-1"] }),
            countFilter({ check_id: ["iam_user_no_mfa"] }),
            countFilter({ resource_regions: ["us-east-1"] }),
            countFilter({ resource_services: ["iam"] }),
            countFilter({ categories: ["identity-security"] }),
            countFilter({ resource_groups: ["prod"] }),
            countFilter({ resource_types: ["AWS::IAM::User"] }),
            countFilter({ resource_uid: ["arn:aws:iam::123:user/alice"] }),
          ],
        },
        recipientEmails: ["security@example.com", "ops@example.com"],
      });
      expect(payload).not.toHaveProperty("method");
    });

    it("should normalize an edited alert to a simple condition instead of preserving an advanced condition", () => {
      // Given / When
      const payload = toAlertPayload(baseValues, advancedCondition);

      // Then
      expect(payload.condition).not.toBe(advancedCondition);
      expect(payload.condition).toEqual(
        expect.objectContaining({
          op: ALERT_BOOLEAN_OPS.AND,
        }),
      );
      expect(payload.trigger).toBe(ALERT_TRIGGER_KINDS.DAILY);
    });

    it("should build supported Findings-equivalent filters without Date or Status", () => {
      // Given / When
      const condition = buildAlertCondition({
        operator: "all",
        children: [
          { kind: "filter", field: "providers", values: ["gcp"] },
          { kind: "filter", field: "accounts", values: ["provider-2"] },
          { kind: "filter", field: "checkStatuses", values: ["FAIL"] },
          { kind: "filter", field: "checkSeverities", values: ["medium"] },
          { kind: "filter", field: "resources", values: ["resource-1"] },
          { kind: "filter", field: "regions", values: ["global"] },
          { kind: "filter", field: "services", values: ["compute"] },
          { kind: "filter", field: "categories", values: ["forensics"] },
          { kind: "filter", field: "resourceGroups", values: ["prod"] },
          { kind: "filter", field: "type", values: ["new"] },
          {
            kind: "group",
            operator: "any",
            children: [
              { kind: "filter", field: "checks", values: ["gcp_check"] },
              { kind: "filter", field: "regions", values: ["europe-west1"] },
            ],
          },
        ],
      });

      // Then
      expect(condition).toEqual({
        op: ALERT_BOOLEAN_OPS.AND,
        children: [
          countFilter({ provider_type: ["gcp"] }),
          countFilter({ provider_id: ["provider-2"] }),
          countFilter({ severity: ["medium"] }),
          countFilter({ resource_uid: ["resource-1"] }),
          countFilter({ resource_regions: ["global"] }),
          countFilter({ resource_services: ["compute"] }),
          countFilter({ categories: ["forensics"] }),
          countFilter({ resource_groups: ["prod"] }),
          countFilter({ delta: ["new"] }),
          {
            op: ALERT_BOOLEAN_OPS.OR,
            children: [
              countFilter({ check_id: ["gcp_check"] }),
              countFilter({ resource_regions: ["europe-west1"] }),
            ],
          },
        ],
      });
      expect(JSON.stringify(condition)).not.toContain("status");
      expect(JSON.stringify(condition)).not.toContain("muted");
      expect(JSON.stringify(condition)).not.toContain("inserted_at");
    });

    it("should prefill modal defaults from active Findings filters and drop unsupported fields", () => {
      // Given / When
      const defaults = getAlertFormDefaultsFromFindingsFilters({
        "filter[provider_type__in]": "aws,gcp",
        "filter[provider_id__in]": "provider-1",
        "filter[severity__in]": "critical,high",
        "filter[delta__in]": "new",
        "filter[region__in]": "us-east-1",
        "filter[service__in]": "iam",
        "filter[category__in]": "identity-security",
        "filter[resource_groups__in]": "prod",
        "filter[check_id__in]": "iam_user_no_mfa",
        "filter[resource_uid__in]": "arn:aws:iam::123:user/alice",
        "filter[status__in]": "FAIL",
        "filter[resource_type__in]": "AWS::IAM::User",
        "filter[inserted_at]": "2026-01-01",
        "filter[muted]": "false",
      });

      // Then
      expect(defaults.filterGroup.children).toEqual([
        { kind: "filter", field: "providers", values: ["aws", "gcp"] },
        { kind: "filter", field: "accounts", values: ["provider-1"] },
        {
          kind: "filter",
          field: "checkSeverities",
          values: ["critical", "high"],
        },
        { kind: "filter", field: "type", values: ["new"] },
        { kind: "filter", field: "regions", values: ["us-east-1"] },
        { kind: "filter", field: "services", values: ["iam"] },
        {
          kind: "filter",
          field: "categories",
          values: ["identity-security"],
        },
        { kind: "filter", field: "resourceGroups", values: ["prod"] },
        { kind: "filter", field: "checks", values: ["iam_user_no_mfa"] },
        {
          kind: "filter",
          field: "resourceTypes",
          values: ["AWS::IAM::User"],
        },
        {
          kind: "filter",
          field: "resources",
          values: ["arn:aws:iam::123:user/alice"],
        },
      ]);
      expect(JSON.stringify(defaults.filterGroup)).not.toContain("inserted_at");
      expect(JSON.stringify(defaults.filterGroup)).not.toContain("status");
      expect(JSON.stringify(defaults.filterGroup)).not.toContain("muted");
    });

    it("should keep ALL type as an unbounded delta while NEW maps to delta=new", () => {
      // Given / When
      const condition = buildAlertCondition({
        operator: "any",
        children: [
          { kind: "filter", field: "type", values: ["all"] },
          { kind: "filter", field: "type", values: ["new"] },
        ],
      });

      // Then
      expect(condition).toEqual({
        ...countFilter({ delta: ["new"] }),
      });
    });

    it("should build a broad threshold-one condition when no portable filter remains", () => {
      // Given / When
      const condition = buildAlertCondition({
        operator: "all",
        children: [],
      });

      // Then
      expect(condition).toEqual(
        countFilter({
          severity: ["critical", "high", "medium", "low", "informational"],
        }),
      );
    });
  });

  describe("edit defaults", () => {
    it("should hydrate simple defaults from an existing severity-only alert", () => {
      // Given / When
      const defaults = getAlertFormDefaults(existingRule);

      // Then
      expect(defaults).toEqual({
        name: "Existing alert",
        description: "Existing description",
        method: "email",
        frequency: ALERT_TRIGGER_KINDS.BOTH,
        filterGroup: {
          operator: "all",
          children: [
            {
              kind: "filter",
              field: "checkSeverities",
              values: ["medium", "low"],
            },
          ],
        },
        severities: ["medium", "low"],
        deltas: [],
        providerTypes: [],
        providerIds: [],
        checkIds: [],
        categories: [],
        regions: [],
        services: [],
        resourceGroups: [],
        resourceTypes: [],
        recipientEmails: ["alerts@example.com"],
        enabled: false,
        advancedCondition: null,
      });
    });

    it("should extract supported filters from advanced conditions and allow simple edits", () => {
      // Given
      const alert = {
        ...existingRule,
        attributes: {
          ...existingRule.attributes,
          condition: {
            op: ALERT_BOOLEAN_OPS.NOT,
            child: {
              op: ALERT_BOOLEAN_OPS.AND,
              children: [
                countFilter({ severity: ["critical"] }),
                countFilter({ provider_type: ["aws"] }),
                countFilter({ status: ["FAIL"] } as AlertLeafFilter),
              ],
            },
          },
        },
      } satisfies AlertRule;

      // When
      const defaults = getAlertFormDefaults(alert);

      // Then
      expect(defaults.filterGroup.children).toEqual([
        {
          kind: "filter",
          field: "checkSeverities",
          values: ["critical"],
        },
        { kind: "filter", field: "providers", values: ["aws"] },
      ]);
      expect(defaults.advancedCondition).toBeNull();
    });
  });
});
