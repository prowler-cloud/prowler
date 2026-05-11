import { SEVERITY_LEVELS } from "@/types/severities";

// Canonical DSL vocabulary and resource types for the Alerts UI.
// Mirrors api/src/backend/alerts/dsl.py — every constant declared here MUST
// match the API. Drift is a bug; reviewers compare the two files when either
// changes.

// ---- operator vocabulary -------------------------------------------------

export const ALERT_BOOLEAN_OPS = {
  AND: "and",
  OR: "or",
  NOT: "not",
} as const;

export const ALERT_AGGREGATE_OPS = {
  COUNT_GTE: "count_gte",
  COUNT_LTE: "count_lte",
  ANY: "any",
  NONE: "none",
} as const;

// ---- filter field vocabulary --------------------------------------------

export const ALERT_FILTER_FIELDS = {
  SEVERITY: "severity",
  DELTA: "delta",
  CHECK_ID: "check_id",
  FINDING_GROUP_ID: "finding_group_id",
  CATEGORIES: "categories",
  RESOURCE_REGIONS: "resource_regions",
  RESOURCE_SERVICES: "resource_services",
  RESOURCE_TYPES: "resource_types",
  RESOURCE_UID: "resource_uid",
  RESOURCE_GROUPS: "resource_groups",
  PROVIDER_ID: "provider_id",
  PROVIDER_TYPE: "provider_type",
} as const;
export type AlertFilterField =
  (typeof ALERT_FILTER_FIELDS)[keyof typeof ALERT_FILTER_FIELDS];

// Closed enum for severity, the only filter field whose values are bounded
// and consumed by the seed flow.
export const ALERT_SEVERITY_VALUES = SEVERITY_LEVELS;

// ---- limits --------------------------------------------------------------

export const ALERT_SCHEMA_VERSION = 1 as const;

// ---- triggers ------------------------------------------------------------

export const ALERT_TRIGGER_KINDS = {
  AFTER_SCAN: "after_scan",
  DAILY: "daily",
  BOTH: "both",
} as const;
export type AlertTriggerKind =
  (typeof ALERT_TRIGGER_KINDS)[keyof typeof ALERT_TRIGGER_KINDS];

export const ALERT_TRIGGER_KIND_VALUES = Object.values(
  ALERT_TRIGGER_KINDS,
) as readonly AlertTriggerKind[];

// ---- recipient lifecycle -------------------------------------------------

export const ALERT_RECIPIENT_STATUS = {
  PENDING: "pending",
  CONFIRMED: "confirmed",
  UNSUBSCRIBED: "unsubscribed",
  BOUNCED: "bounced",
} as const;
export type AlertRecipientStatus =
  (typeof ALERT_RECIPIENT_STATUS)[keyof typeof ALERT_RECIPIENT_STATUS];

// ---- discriminated condition union --------------------------------------

// Leaf filter is a partial mapping from a whitelisted field name to its
// validated value. Kept loose at the type level (the Zod schema in
// ./lib/schemas.ts does the strict per-kind validation).
export type AlertLeafFilterValue = string[] | boolean;
export type AlertLeafFilter = Partial<
  Record<AlertFilterField, AlertLeafFilterValue>
>;

export interface AlertConditionAnd {
  op: typeof ALERT_BOOLEAN_OPS.AND;
  children: AlertCondition[];
}

export interface AlertConditionOr {
  op: typeof ALERT_BOOLEAN_OPS.OR;
  children: AlertCondition[];
}

export interface AlertConditionNot {
  op: typeof ALERT_BOOLEAN_OPS.NOT;
  child: AlertCondition;
}

export interface AlertConditionCountGte {
  op: typeof ALERT_AGGREGATE_OPS.COUNT_GTE;
  filter: AlertLeafFilter;
  value: number;
}

export interface AlertConditionCountLte {
  op: typeof ALERT_AGGREGATE_OPS.COUNT_LTE;
  filter: AlertLeafFilter;
  value: number;
}

export interface AlertConditionAny {
  op: typeof ALERT_AGGREGATE_OPS.ANY;
  filter: AlertLeafFilter;
}

export interface AlertConditionNone {
  op: typeof ALERT_AGGREGATE_OPS.NONE;
  filter: AlertLeafFilter;
}

export type AlertConditionGroup =
  | AlertConditionAnd
  | AlertConditionOr
  | AlertConditionNot;

export type AlertConditionLeaf =
  | AlertConditionCountGte
  | AlertConditionCountLte
  | AlertConditionAny
  | AlertConditionNone;

export type AlertCondition = AlertConditionGroup | AlertConditionLeaf;

// ---- resource attribute shapes ------------------------------------------

export interface AlertRuleAttributes {
  name: string;
  description: string;
  enabled: boolean;
  trigger: AlertTriggerKind;
  condition: AlertCondition;
  schema_version: number;
  /**
   * Emails of the recipients attached to the rule. The API exposes the
   * relationship as a list of email strings (write- and read-side via the
   * `recipient_emails` attribute), not as a JSON:API relationships block.
   */
  recipient_emails?: string[];
  created_by?: string | null;
  inserted_at: string;
  updated_at: string;
}

export interface AlertRecipientAttributes {
  email: string;
  status: AlertRecipientStatus;
  confirmation_sent_at?: string | null;
  confirmation_expires_at?: string | null;
  confirmed_at?: string | null;
  unsubscribed_at?: string | null;
  last_bounce_at?: string | null;
  inserted_at: string;
  updated_at: string;
}

export interface AlertPreviewSummary {
  finding_count_total?: number;
  counts_by_severity?: Record<string, number>;
  top_severity?: string;
  top_findings?: string[];
  deep_link_filter_hint?: Record<string, unknown>;
}

export interface AlertPreviewResponse {
  summary: AlertPreviewSummary;
  sample_finding_ids?: string[];
  evaluation_failed: boolean;
  last_error?: string | null;
  summary_fallback?: boolean;
  duration_ms?: number;
}

// ---- JSON:API envelopes --------------------------------------------------

export interface JsonApiRelationshipRef {
  id: string;
  type: string;
}

export interface JsonApiRelationship {
  data: JsonApiRelationshipRef | JsonApiRelationshipRef[] | null;
}

export interface AlertRule {
  id: string;
  type: "alert-rules";
  attributes: AlertRuleAttributes;
  relationships?: {
    recipients?: JsonApiRelationship;
    last_event?: JsonApiRelationship;
  };
}

export interface AlertRecipient {
  id: string;
  type: "alert-recipients";
  attributes: AlertRecipientAttributes;
  relationships?: {
    rules?: JsonApiRelationship;
  };
}

// ---- seeding payloads ----------------------------------------------------

export type AlertsFilterBag = Record<string, string | string[]>;
