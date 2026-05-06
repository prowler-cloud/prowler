import type {
  AlertCondition,
  AlertTriggerKind,
} from "@/app/(prowler)/alerts/_types";

export const ALERT_FILTER_OPERATORS = {
  ALL: "all",
  ANY: "any",
} as const;

export type AlertFormFilterOperator =
  (typeof ALERT_FILTER_OPERATORS)[keyof typeof ALERT_FILTER_OPERATORS];

export const ALERT_FILTER_FIELDS = {
  PROVIDERS: "providers",
  ACCOUNTS: "accounts",
  CHECK_STATUSES: "checkStatuses",
  CHECK_SEVERITIES: "checkSeverities",
  RESOURCES: "resources",
  RESOURCE_TYPES: "resourceTypes",
  REGIONS: "regions",
  SERVICES: "services",
  CATEGORIES: "categories",
  RESOURCE_GROUPS: "resourceGroups",
  FINDING_GROUPS: "findingGroups",
  ACCOUNT_TAGS: "accountTags",
  TYPE: "type",
  DATA_DATE_WINDOW: "dataDateWindow",
  INCLUDE_MUTED_FINDINGS: "includeMutedFindings",
  CHECKS: "checks",
} as const;

export type AlertFormFilterField =
  (typeof ALERT_FILTER_FIELDS)[keyof typeof ALERT_FILTER_FIELDS];

export const ALERT_FINDING_TYPES = {
  NEW: "new",
  ALL: "all",
} as const;

export type AlertFormFindingType =
  (typeof ALERT_FINDING_TYPES)[keyof typeof ALERT_FINDING_TYPES];

export interface AlertFormFilterItem {
  kind: "filter";
  field: AlertFormFilterField;
  values: string[];
}

export interface AlertFormFilterGroup {
  kind?: "group";
  operator: AlertFormFilterOperator;
  children: AlertFormFilterNode[];
}

export type AlertFormFilterNode =
  | AlertFormFilterItem
  | (AlertFormFilterGroup & { kind: "group" });

export const ALERT_NOTIFICATION_METHODS = {
  EMAIL: "email",
} as const;

export type AlertNotificationMethod =
  (typeof ALERT_NOTIFICATION_METHODS)[keyof typeof ALERT_NOTIFICATION_METHODS];

export const ALERT_NOTIFICATION_METHOD_OPTIONS = [
  {
    value: ALERT_NOTIFICATION_METHODS.EMAIL,
    label: "Email",
  },
] as const;

export interface AlertFormValues {
  name: string;
  description: string;
  method: AlertNotificationMethod;
  frequency: AlertTriggerKind;
  condition: AlertCondition;
  recipientEmails: string[];
  enabled: boolean;
}

export interface AlertFormDefaults extends AlertFormValues {
  advancedCondition: AlertCondition | null;
}

export interface AlertFormSubmitResult {
  ok: boolean;
  alertId?: string;
  error?: string;
}

export type AlertFormFindingFilterBag = Record<string, string | string[]>;
