// Realtime (real-time compliance for AWS). Prowler Cloud only. Attribute names
// mirror the API (`api/src/backend/realtime/v1/serializers.py`), so the shapes
// below keep the API's snake_case.

export const REALTIME_MODE = {
  MONITOR: "monitor",
  PR: "pr",
  AUTO: "auto",
} as const;
export type RealtimeMode = (typeof REALTIME_MODE)[keyof typeof REALTIME_MODE];

/** Severities a policy can use as its floor. */
export const REALTIME_MIN_SEVERITY = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;
export type RealtimeMinSeverity =
  (typeof REALTIME_MIN_SEVERITY)[keyof typeof REALTIME_MIN_SEVERITY];

export const REALTIME_FEED_STATUS = {
  NOT_CONFIGURED: "not_configured",
  CONNECTED: "connected",
  ERROR: "error",
} as const;
export type RealtimeFeedStatus =
  (typeof REALTIME_FEED_STATUS)[keyof typeof REALTIME_FEED_STATUS];

export const REALTIME_DETECTION_STATUS = {
  NEW: "new",
  VIOLATION: "violation",
  COMPLIANT: "compliant",
  OUT_OF_SCOPE: "out_of_scope",
  ERROR: "error",
} as const;
export type RealtimeDetectionStatus =
  (typeof REALTIME_DETECTION_STATUS)[keyof typeof REALTIME_DETECTION_STATUS];

export const REALTIME_ACTION_KIND = {
  SELF_FIX: "self_fix",
  CODE: "code",
  PROPOSAL: "proposal",
} as const;
export type RealtimeActionKind =
  (typeof REALTIME_ACTION_KIND)[keyof typeof REALTIME_ACTION_KIND];

export const REALTIME_ACTION_STATUS = {
  DRY_RUN: "dry_run",
  APPLIED: "applied",
  FIXED_VERIFIED: "fixed_verified",
  FIX_FAILED: "fix_failed",
  STILL_FAILING: "still_failing",
  PR_OPENED: "pr_opened",
  PR_READY: "pr_ready",
  PR_BLOCKED: "pr_blocked",
  QUEUED: "queued",
  NOT_IN_CODE: "not_in_code",
  REVERTED: "reverted",
} as const;
export type RealtimeActionStatus =
  (typeof REALTIME_ACTION_STATUS)[keyof typeof REALTIME_ACTION_STATUS];

/** How a finding would be handled under the current policy. */
export const REALTIME_ROUTE = {
  AUTO: "auto",
  PR: "pr",
  MANUAL: "manual",
  /** Outside the compliance frameworks the policy enforces: detected, never fixed. */
  NOT_ENFORCED: "not_enforced",
} as const;
export type RealtimeRoute =
  (typeof REALTIME_ROUTE)[keyof typeof REALTIME_ROUTE];

export const REALTIME_DATA_STORE = {
  OK: "ok",
  NOT_CONFIGURED: "not_configured",
  UNAVAILABLE: "unavailable",
} as const;
export type RealtimeDataStore =
  (typeof REALTIME_DATA_STORE)[keyof typeof REALTIME_DATA_STORE];

export const REALTIME_INSIGHT_KIND = {
  OVERVIEW: "overview",
  FINDINGS: "findings",
  COST: "cost",
  ANOMALY: "anomaly",
  SIMULATION: "simulation",
  TIMELINE: "timeline",
  STATUS: "status",
} as const;
export type RealtimeInsightKind =
  (typeof REALTIME_INSIGHT_KIND)[keyof typeof REALTIME_INSIGHT_KIND];

export const REALTIME_TAB = {
  OVERVIEW: "overview",
  STREAM: "stream",
  FINDINGS: "findings",
  REMEDIATION: "remediation",
  STATUS: "status",
} as const;
export type RealtimeTab = (typeof REALTIME_TAB)[keyof typeof REALTIME_TAB];

/** Steps of the setup wizard as the API reports them (`insights/setup`). */
export const REALTIME_SETUP_STEP = {
  FEED: "feed",
  ENFORCEMENT: "enforcement",
  REMEDIATION: "remediation",
  ALERTS: "alerts",
  COST: "cost",
  ACTIVATE: "activate",
} as const;
export type RealtimeSetupStepId =
  (typeof REALTIME_SETUP_STEP)[keyof typeof REALTIME_SETUP_STEP];

/** Sample data kinds (`GET /realtime/demo/{kind}`): the insight views plus the lists. */
export const REALTIME_DEMO_LIST_KIND = {
  EVENTS: "events",
  DETECTIONS: "detections",
  ACTIONS: "actions",
} as const;
export type RealtimeDemoListKind =
  (typeof REALTIME_DEMO_LIST_KIND)[keyof typeof REALTIME_DEMO_LIST_KIND];

/** Statuses of a person's alert destination (`notification-targets`). */
export const REALTIME_RECIPIENT_STATUS = {
  CONFIRMED: "confirmed",
} as const;

/** Most tag filters a scope can hold (API: `MAX_SCOPE_TAGS`). */
export const REALTIME_MAX_SCOPE_TAGS = 10;

/** Most compliance frameworks a policy can enforce (API: `MAX_ENFORCED_FRAMEWORKS`). */
export const REALTIME_MAX_FRAMEWORKS = 5;

/** Cost anomaly threshold ranges (API: `_validate_policy_fields`). */
export const REALTIME_COST_RATIO_RANGE = { min: 1.1, max: 20 } as const;
export const REALTIME_COST_DELTA_RANGE = { min: 0, max: 100000 } as const;

/** Detections raised by the compliance drift reconciler carry this rule id. */
export const REALTIME_DRIFT_RULE_ID = "framework_drift";

// ------------------------------------------------------------------ resources

/** Where alerts for detected actions go (policy field `notifications`). */
export interface RealtimeSlackAlerts {
  enabled: boolean;
  channel_ids: string[];
}

export interface RealtimeEmailAlerts {
  enabled: boolean;
  recipient_ids: string[];
}

export interface RealtimeNotifications {
  min_severity: RealtimeMinSeverity;
  slack: RealtimeSlackAlerts;
  email: RealtimeEmailAlerts;
}

export interface RealtimePolicy {
  id: string;
  provider_id: string;
  enabled: boolean;
  mode: RealtimeMode;
  dry_run: boolean;
  min_severity: RealtimeMinSeverity;
  deny_checks: string[];
  allow_regions: string[];
  scope_tags: Record<string, string>;
  iac_repo: string;
  iac_path: string;
  open_pr: boolean;
  /** Let Lighthouse AI write the code change for checks without a built-in patcher. */
  use_lighthouse: boolean;
  /** Framework ids remediation is limited to; empty means every check. */
  frameworks: string[];
  cost_anomaly_enabled: boolean;
  cost_anomaly_min_ratio: number;
  cost_anomaly_min_delta: number;
  notifications: RealtimeNotifications;
}

/** What the cost anomalies page edits. */
export type RealtimeCostAnomalySettings = Pick<
  RealtimePolicy,
  "cost_anomaly_enabled" | "cost_anomaly_min_ratio" | "cost_anomaly_min_delta"
>;

/** A compliance framework a policy can enforce (`GET /realtime/frameworks`). */
export interface RealtimeFramework {
  id: string;
  name: string;
  version: string;
}

/** What the policy form edits and the API accepts. */
export type RealtimePolicyInput = Omit<RealtimePolicy, "id" | "provider_id">;

/** A Slack channel an alert can go to. */
export interface RealtimeSlackTarget {
  integration_id: string;
  channel_id: string;
  name: string;
}

/** An alert recipient; only `confirmed` ones can receive alerts. */
export interface RealtimeEmailTarget {
  id: string;
  email: string;
  status: string;
}

export interface RealtimeNotificationTargets {
  slack: RealtimeSlackTarget[];
  email: RealtimeEmailTarget[];
}

/** One fix the remediation role makes possible (`GET /realtime/remediations`). */
export interface RealtimeRemediation {
  id: string;
  title: string;
  effect: string;
  checks: string[];
  /** The checks that are inside the frameworks the policy enforces. */
  active_checks: string[];
  iam_actions: string[];
  revertible: boolean;
  undo: string;
  in_enforced_scope: boolean;
}

export interface RealtimeFeed {
  id: string;
  provider_id: string;
  queue_url: string;
  region: string;
  status: RealtimeFeedStatus;
  last_polled_at: string | null;
  last_event_at: string | null;
  last_error: string;
}

export interface RealtimeFeedInput {
  queue_url: string;
  region: string;
}

export interface RealtimeCredential {
  id: string;
  provider_id: string;
  role_arn: string;
  has_github_token: boolean;
}

/** Write-only secrets: any subset, and a role always travels with its external id. */
export interface RealtimeCredentialInput {
  role_arn?: string;
  external_id?: string;
  github_token?: string;
}

export interface RealtimeDetection {
  id: string;
  provider_id: string;
  event_id: string;
  event_time: string;
  region: string;
  rule_id: string;
  title: string;
  severity: string;
  actor: string;
  resource: string;
  check_ids: string[];
  requirements: string[];
  status: RealtimeDetectionStatus;
  note: string;
  verified_at: string | null;
}

export interface RealtimeAction {
  id: string;
  provider_id: string;
  detection_id: string | null;
  kind: RealtimeActionKind;
  status: RealtimeActionStatus;
  check_id: string;
  resource_uid: string;
  region: string;
  severity: string;
  summary: string;
  pr_url: string;
  branch: string;
  revertible: boolean;
  inserted_at: string;
}

export interface RealtimeEvent {
  id: string;
  event_time: string;
  region: string;
  event_source: string;
  event_name: string;
  user_type: string;
  user_arn: string;
  source_ip: string;
  error_code: string;
  read_only: boolean;
  provider_id: string;
  detection_status: RealtimeDetectionStatus | null;
  rule_id: string | null;
}

export interface RealtimeHealth {
  enabled: boolean;
  clickhouse: RealtimeDataStore;
  events_last_hour: number;
  changes_last_hour: number;
}

export interface RealtimePage<T> {
  items: T[];
  page: number;
  pages: number;
  count: number;
}

// ------------------------------------------------------------------- insights

export interface RealtimeOverviewProvider {
  id: string;
  uid: string;
  alias: string | null;
}

export interface RealtimeOverviewPolicy {
  enabled: boolean;
  mode: RealtimeMode;
  dry_run: boolean;
  scope_tags: Record<string, string>;
}

export interface RealtimeOverviewFeed {
  status: RealtimeFeedStatus;
  /** `sqs` is real time; `lookup` is CloudTrail LookupEvents, minutes behind. */
  source: "sqs" | "lookup";
  last_event_at: string | null;
  last_error: string;
}

export interface RealtimeEventStats {
  events: number;
  changes: number;
}

export interface RealtimeCostOff {
  enabled: false;
}

/** One anomaly: `id` is `"<service>|<region>"`, the key of its detail page. */
export interface RealtimeCostAnomaly {
  id: string;
  service: string;
  region: string;
  short_service: string;
  today: number;
  base: number;
  delta: number;
  ratio: number;
}

export interface RealtimeCostOn {
  enabled: true;
  /** False when the data store has no cost figures to give right now. */
  available: boolean;
  total?: number;
  today?: number;
  anomaly_count: number;
  /** The top five; the Findings tab lists them all. */
  anomalies: RealtimeCostAnomaly[];
}

export type RealtimeOverviewCost = RealtimeCostOff | RealtimeCostOn;

export interface RealtimePosture {
  passed: number;
  failed: number;
  muted: number;
  /** Null until a scan has produced a summary. */
  score: number | null;
  failed_by_severity: Record<string, number>;
  has_scan: boolean;
}

export interface RealtimeOverviewPayload {
  provider: RealtimeOverviewProvider;
  policy: RealtimeOverviewPolicy | null;
  feed: RealtimeOverviewFeed | null;
  data_store: RealtimeDataStore;
  events_last_hour: RealtimeEventStats | null;
  cost: RealtimeOverviewCost;
  posture: RealtimePosture;
  detections: Record<string, number>;
  actions: Record<string, number>;
}

export interface RealtimeSignal {
  signal: string;
  service: string;
  region: string;
  count: number;
}

export interface RealtimeRankedFinding {
  finding_id: string;
  check_id: string;
  severity: string;
  title: string;
  service: string;
  resource_uid: string;
  region: string;
  status_extended: string;
  score: number;
  reasons: string[];
  route: RealtimeRoute;
}

export interface RealtimeFindingsPayload {
  signals: RealtimeSignal[];
  findings: RealtimeRankedFinding[];
}

export interface RealtimeCostDay {
  day: string;
  amount: number;
}

export interface RealtimeCostSeries {
  service: string;
  region: string;
  days: RealtimeCostDay[];
  latest: number;
  base: number;
}

export interface RealtimeCostTotal {
  total: number;
  today: number;
}

export interface RealtimeCostThresholds {
  min_ratio: number;
  min_delta: number;
}

export interface RealtimeCostPayloadOn {
  enabled: true;
  total: RealtimeCostTotal;
  series: RealtimeCostSeries[];
  anomalies: RealtimeCostAnomaly[];
  thresholds: RealtimeCostThresholds;
}

export type RealtimeCostPayload = RealtimeCostOff | RealtimeCostPayloadOn;

/** A recent change (write call) in the anomalous service. */
export interface RealtimeAnomalyEvent {
  event_id: string;
  event_time: string;
  region: string;
  event_source: string;
  event_name: string;
  user_type: string;
  user_arn: string;
  source_ip: string;
  error_code: string;
}

export interface RealtimeAnomalyPayload {
  /** Null when the spike is over but the series is still known. */
  anomaly: RealtimeCostAnomaly | null;
  short_service: string;
  series: RealtimeCostDay[];
  thresholds: RealtimeCostThresholds;
  events: RealtimeAnomalyEvent[];
  findings: RealtimeRankedFinding[];
}

export interface RealtimeSimulationEffect {
  check_id: string;
  effect: string;
  resources: number;
}

export interface RealtimeSimulationPayload {
  open: number;
  would_fix_in_account: number;
  would_propose_in_code: number;
  needs_a_person: number;
  /** Open findings outside the enforced frameworks: never fixed, only detected. */
  outside_frameworks: number;
  /** Framework ids the policy enforces; empty means every check. */
  frameworks: string[];
  dry_run: boolean;
  mode: RealtimeMode;
  effects: RealtimeSimulationEffect[];
  projected_open_after_auto: number;
  automation_share: number;
}

export interface RealtimeTimelinePoint {
  at: string;
  passed: number;
  failed: number;
}

export interface RealtimeTimelineAction {
  at: string;
  kind: RealtimeActionKind;
  status: RealtimeActionStatus;
  summary: string;
}

export interface RealtimeTimelinePayload {
  points: RealtimeTimelinePoint[];
  actions: RealtimeTimelineAction[];
}

export interface RealtimeStatusPayload {
  generated_on: string;
  mode: RealtimeMode | "off";
  scope: string;
  checks_passing: number;
  checks_failing: number;
  failing_by_severity: Record<string, number>;
  fixed_and_verified_last_30_days: number;
  sha256: string;
}

export interface RealtimeSetupStep {
  id: RealtimeSetupStepId;
  required: boolean;
  done: boolean;
  detail: string | null;
}

/** Where a provider stands in the setup wizard (`insights/setup`). */
export interface RealtimeSetupPayload {
  activated: boolean;
  /** The first required step that is not done; null once activated. */
  next_step: RealtimeSetupStepId | null;
  steps: RealtimeSetupStep[];
}

export interface RealtimeInsightPayloads {
  overview: RealtimeOverviewPayload;
  findings: RealtimeFindingsPayload;
  cost: RealtimeCostPayload;
  anomaly: RealtimeAnomalyPayload;
  simulation: RealtimeSimulationPayload;
  timeline: RealtimeTimelinePayload;
  status: RealtimeStatusPayload;
}

/** What `getRealtimeDemo(kind)` returns, per kind. */
export interface RealtimeDemoPayloads extends RealtimeInsightPayloads {
  events: RealtimePage<RealtimeEvent>;
  detections: RealtimePage<RealtimeDetection>;
  actions: RealtimePage<RealtimeAction>;
}
export type RealtimeDemoKind = keyof RealtimeDemoPayloads;

// -------------------------------------------------------------------- results

export interface RealtimeSuccess<T> {
  ok: true;
  data: T;
}

export interface RealtimeFailure {
  ok: false;
  /** HTTP status of the failing call (0 when the API was unreachable). */
  status: number;
  error: string;
  /** Per-attribute messages from a 400, keyed by attribute name. */
  fieldErrors?: Record<string, string>;
}

export type RealtimeResult<T> = RealtimeSuccess<T> | RealtimeFailure;

// ------------------------------------------------------------------ raw JSON:API

export interface RealtimeApiResource {
  id: string;
  type: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<
    string,
    { data?: { id: string; type: string } | null } | undefined
  >;
}

export interface RealtimeApiDocument {
  data?: RealtimeApiResource | RealtimeApiResource[];
  meta?: { pagination?: { page?: number; pages?: number; count?: number } };
}

export interface RealtimeApiError {
  detail?: string;
  source?: { pointer?: string };
}
