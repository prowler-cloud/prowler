import type { AlertPayload } from "@/app/(prowler)/alerts/_actions/alerts";
import {
  ALERT_AGGREGATE_OPS,
  ALERT_SEVERITY_VALUES,
  ALERT_TRIGGER_KINDS,
  type AlertCondition,
  type AlertLeafFilter,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";

import {
  ALERT_NOTIFICATION_METHODS,
  type AlertFormDefaults,
  type AlertFormValues,
} from "../_types/alert-form";

const DEFAULT_CONDITION: AlertCondition = {
  op: ALERT_AGGREGATE_OPS.COUNT_GTE,
  filter: { severity: [...ALERT_SEVERITY_VALUES] },
  value: 1,
};

const normalizeRecipientEmails = (emails: string[]): string[] =>
  emails
    .map((email) => email.trim().toLowerCase())
    .filter((email) => email.length > 0);

export const toAlertPayload = (values: AlertFormValues): AlertPayload => ({
  name: values.name.trim(),
  description: values.description.trim(),
  enabled: values.enabled,
  trigger: values.frequency,
  condition: values.condition,
  recipientEmails: normalizeRecipientEmails(values.recipientEmails),
});

export const getEmptyAlertFormDefaults = (
  frequency: AlertFormValues["frequency"] = ALERT_TRIGGER_KINDS.AFTER_SCAN,
  condition: AlertCondition = DEFAULT_CONDITION,
): AlertFormDefaults => ({
  name: "",
  description: "",
  method: ALERT_NOTIFICATION_METHODS.EMAIL,
  frequency,
  condition,
  recipientEmails: [],
  enabled: true,
  advancedCondition: null,
});

export const getAlertFormDefaults = (alert: AlertRule): AlertFormDefaults => ({
  name: alert.attributes.name,
  description: alert.attributes.description,
  method: ALERT_NOTIFICATION_METHODS.EMAIL,
  frequency: alert.attributes.trigger,
  condition: alert.attributes.condition,
  recipientEmails: alert.attributes.recipient_emails ?? [],
  enabled: alert.attributes.enabled,
  advancedCondition: null,
});

const SIMPLE_FIELD_TO_FINDINGS_FILTER: Partial<
  Record<keyof AlertLeafFilter, string>
> = {
  provider_type: "filter[provider_type__in]",
  provider_id: "filter[provider_id__in]",
  severity: "filter[severity__in]",
  delta: "filter[delta]",
  resource_regions: "filter[region__in]",
  resource_services: "filter[service__in]",
  resource_types: "filter[resource_type__in]",
  categories: "filter[category__in]",
  resource_groups: "filter[resource_groups__in]",
  check_id: "filter[check_id__in]",
  finding_group_id: "filter[finding_group_id]",
  resource_uid: "filter[resource_uid__in]",
};

const uniqueValues = (values: string[]): string[] =>
  Array.from(new Set(values));

const addFilterValues = (
  filters: Record<string, string[]>,
  field: keyof AlertLeafFilter,
  value: AlertLeafFilter[keyof AlertLeafFilter],
): Record<string, string[]> => {
  const filterKey = SIMPLE_FIELD_TO_FINDINGS_FILTER[field];
  if (!filterKey || !Array.isArray(value)) return filters;

  filters[filterKey] = uniqueValues([...(filters[filterKey] ?? []), ...value]);
  return filters;
};

export const getFindingsFiltersFromAlertCondition = (
  condition: AlertCondition,
): Record<string, string[]> => {
  if ("filter" in condition) {
    return Object.entries(condition.filter).reduce<Record<string, string[]>>(
      (filters, [field, value]) =>
        addFilterValues(
          filters,
          field as keyof AlertLeafFilter,
          value as AlertLeafFilter[keyof AlertLeafFilter],
        ),
      {},
    );
  }

  if ("child" in condition) {
    return getFindingsFiltersFromAlertCondition(condition.child);
  }

  return condition.children.reduce<Record<string, string[]>>(
    (filters, child) => {
      const childFilters = getFindingsFiltersFromAlertCondition(child);
      Object.entries(childFilters).forEach(([filterKey, values]) => {
        filters[filterKey] = uniqueValues([
          ...(filters[filterKey] ?? []),
          ...values,
        ]);
      });
      return filters;
    },
    {},
  );
};
