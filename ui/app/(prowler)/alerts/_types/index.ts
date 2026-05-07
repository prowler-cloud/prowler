import { FINDING_DELTA } from "@/types/components";
import { PROVIDER_TYPES, type ProviderType } from "@/types/providers";
import { SEVERITY_LEVELS, type SeverityLevel } from "@/types/severities";

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
export type AlertBooleanOp =
  (typeof ALERT_BOOLEAN_OPS)[keyof typeof ALERT_BOOLEAN_OPS];

export const ALERT_AGGREGATE_OPS = {
  COUNT_GTE: "count_gte",
  COUNT_LTE: "count_lte",
  ANY: "any",
  NONE: "none",
} as const;
export type AlertAggregateOp =
  (typeof ALERT_AGGREGATE_OPS)[keyof typeof ALERT_AGGREGATE_OPS];

export const ALERT_BOOLEAN_OP_VALUES = Object.values(
  ALERT_BOOLEAN_OPS,
) as readonly AlertBooleanOp[];
export const ALERT_AGGREGATE_OP_VALUES = Object.values(
  ALERT_AGGREGATE_OPS,
) as readonly AlertAggregateOp[];

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

export const ALERT_FILTER_FIELD_VALUES = Object.values(
  ALERT_FILTER_FIELDS,
) as readonly AlertFilterField[];

// Field-kind classification — drives the value editor rendered by the
// condition builder and the runtime type checks in the validator.
export const ALERT_FILTER_FIELD_KIND = {
  ENUM_LIST: "enum_list",
  BOOLEAN: "boolean",
  UUID_LIST: "uuid_list",
  STRING_LIST: "string_list",
} as const;
export type AlertFilterFieldKind =
  (typeof ALERT_FILTER_FIELD_KIND)[keyof typeof ALERT_FILTER_FIELD_KIND];

export const ALERT_FILTER_FIELD_KIND_BY_FIELD: Readonly<
  Record<AlertFilterField, AlertFilterFieldKind>
> = {
  severity: ALERT_FILTER_FIELD_KIND.ENUM_LIST,
  delta: ALERT_FILTER_FIELD_KIND.ENUM_LIST,
  provider_type: ALERT_FILTER_FIELD_KIND.ENUM_LIST,
  provider_id: ALERT_FILTER_FIELD_KIND.UUID_LIST,
  check_id: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  finding_group_id: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  categories: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  resource_regions: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  resource_services: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  resource_types: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  resource_uid: ALERT_FILTER_FIELD_KIND.STRING_LIST,
  resource_groups: ALERT_FILTER_FIELD_KIND.STRING_LIST,
};

// Closed enums for fields whose values are bounded. Builder uses them to
// render multi-selects; validator uses them to reject out-of-range inputs.
export const ALERT_SEVERITY_VALUES = SEVERITY_LEVELS;
export type AlertSeverity = SeverityLevel;

export const ALERT_DELTA_VALUES = [
  FINDING_DELTA.NEW,
  FINDING_DELTA.CHANGED,
] as const;
export type AlertDelta = (typeof ALERT_DELTA_VALUES)[number];

// Mirrors api.models.Provider.ProviderChoices. Keep in sync if a new
// platform is registered there; the API rejects values outside this set.
export const ALERT_PROVIDER_TYPE_VALUES = PROVIDER_TYPES;
export type AlertProviderType = ProviderType;

export const ALERT_ENUM_VALUES_BY_FIELD = {
  severity: ALERT_SEVERITY_VALUES,
  delta: ALERT_DELTA_VALUES,
  provider_type: ALERT_PROVIDER_TYPE_VALUES,
} as const;

// Forbidden filter fields — the validator rejects these with a clear error
// instead of "unknown field". Mirrors `dsl.py::FORBIDDEN_FILTER_FIELDS`.
export const ALERT_FORBIDDEN_FILTER_FIELDS = [
  "inserted_at",
  "inserted_at__gte",
  "inserted_at__lte",
  "inserted_at__date",
  "updated_at",
  "updated_at__gte",
  "updated_at__lte",
  "first_seen_at",
  "first_seen_at__gte",
  "first_seen_at__lte",
  "search",
  "sort",
  "page",
  "page[number]",
  "page[size]",
  "include",
] as const;
export type AlertForbiddenFilterField =
  (typeof ALERT_FORBIDDEN_FILTER_FIELDS)[number];

// ---- limits --------------------------------------------------------------

export const ALERT_SCHEMA_VERSION = 1 as const;
export const ALERT_MAX_DEPTH = 5 as const;
export const ALERT_MAX_NODES = 100 as const;
export const ALERT_AGGREGATE_VALUE_MIN = 1 as const;
export const ALERT_AGGREGATE_VALUE_MAX = 1_000_000 as const;

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

export const ALERT_RECIPIENT_STATUS_VALUES = Object.values(
  ALERT_RECIPIENT_STATUS,
) as readonly AlertRecipientStatus[];

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
  would_fire: boolean;
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
