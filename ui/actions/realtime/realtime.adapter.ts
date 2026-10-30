import {
  REALTIME_DATA_STORE,
  REALTIME_DETECTION_STATUS,
  REALTIME_FEED_STATUS,
  REALTIME_INSIGHT_KIND,
  REALTIME_MODE,
  REALTIME_MIN_SEVERITY,
  REALTIME_SETUP_STEP,
  type RealtimeAction,
  type RealtimeApiDocument,
  type RealtimeApiError,
  type RealtimeApiResource,
  type RealtimeCredential,
  type RealtimeDetection,
  type RealtimeEvent,
  type RealtimeFeed,
  type RealtimeFramework,
  type RealtimeHealth,
  type RealtimeDemoKind,
  type RealtimeDemoPayloads,
  type RealtimeInsightKind,
  type RealtimeInsightPayloads,
  type RealtimeNotifications,
  type RealtimeNotificationTargets,
  type RealtimePage,
  type RealtimePolicy,
  type RealtimeRemediation,
  type RealtimeSetupPayload,
  type RealtimeSetupStepId,
} from "@/types/realtime";

const asString = (value: unknown, fallback = ""): string =>
  typeof value === "string" ? value : fallback;

const asNullableString = (value: unknown): string | null =>
  typeof value === "string" && value ? value : null;

const asBoolean = (value: unknown, fallback = false): boolean =>
  typeof value === "boolean" ? value : fallback;

const asNumber = (value: unknown, fallback = 0): number =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;

const asStringList = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

const asStringMap = (value: unknown): Record<string, string> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, String(item)]),
      )
    : {};

const oneOf = <T extends string>(
  value: unknown,
  allowed: readonly T[],
  fallback: T,
): T => (allowed.includes(value as T) ? (value as T) : fallback);

const relatedId = (resource: RealtimeApiResource, name: string): string =>
  resource.relationships?.[name]?.data?.id ?? "";

/** The resources of a JSON:API document, whether it holds one or many. */
export const resourcesOf = (
  document: RealtimeApiDocument | undefined,
): RealtimeApiResource[] => {
  const data = document?.data;
  if (!data) return [];
  return Array.isArray(data) ? data : [data];
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

/** The policy's alert settings; anything missing falls back to "nothing is sent". */
export const toNotifications = (value: unknown): RealtimeNotifications => {
  const n = isRecord(value) ? value : {};
  const slack = isRecord(n.slack) ? n.slack : {};
  const email = isRecord(n.email) ? n.email : {};
  return {
    min_severity: oneOf(
      n.min_severity,
      Object.values(REALTIME_MIN_SEVERITY),
      REALTIME_MIN_SEVERITY.HIGH,
    ),
    slack: {
      enabled: asBoolean(slack.enabled),
      channel_ids: asStringList(slack.channel_ids),
    },
    email: {
      enabled: asBoolean(email.enabled),
      recipient_ids: asStringList(email.recipient_ids),
    },
  };
};

export const toPolicy = (resource: RealtimeApiResource): RealtimePolicy => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    provider_id: relatedId(resource, "provider"),
    enabled: asBoolean(a.enabled),
    // Same safe defaults as the API: react in code review, change nothing.
    mode: oneOf(a.mode, Object.values(REALTIME_MODE), REALTIME_MODE.PR),
    dry_run: asBoolean(a.dry_run, true),
    min_severity: oneOf(
      a.min_severity,
      Object.values(REALTIME_MIN_SEVERITY),
      REALTIME_MIN_SEVERITY.LOW,
    ),
    deny_checks: asStringList(a.deny_checks),
    allow_regions: asStringList(a.allow_regions),
    scope_tags: asStringMap(a.scope_tags),
    iac_repo: asString(a.iac_repo),
    iac_path: asString(a.iac_path),
    open_pr: asBoolean(a.open_pr),
    use_lighthouse: asBoolean(a.use_lighthouse, true),
    frameworks: asStringList(a.frameworks),
    cost_anomaly_enabled: asBoolean(a.cost_anomaly_enabled),
    cost_anomaly_min_ratio: asNumber(a.cost_anomaly_min_ratio, 2),
    cost_anomaly_min_delta: asNumber(a.cost_anomaly_min_delta, 5),
    notifications: toNotifications(a.notifications),
  };
};

const asRecords = (value: unknown): Array<Record<string, unknown>> =>
  Array.isArray(value) ? value.filter(isRecord) : [];

/**
 * Where alerts can go. The API sends one `realtime-notification-targets`
 * resource, or a one-element list; both read the same.
 */
export const toNotificationTargets = (
  document: RealtimeApiDocument | undefined,
): RealtimeNotificationTargets => {
  const [resource] = resourcesOf(document);
  const a = resource?.attributes ?? {};
  return {
    slack: asRecords(a.slack)
      .map((item) => ({
        integration_id: asString(item.integration_id),
        channel_id: asString(item.channel_id),
        name: asString(item.name),
      }))
      .filter((item) => item.channel_id),
    email: asRecords(a.email)
      .map((item) => ({
        id: asString(item.id),
        email: asString(item.email),
        status: asString(item.status),
      }))
      .filter((item) => item.id),
  };
};

export const toRemediation = (
  resource: RealtimeApiResource,
): RealtimeRemediation => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    title: asString(a.title, resource.id),
    effect: asString(a.effect),
    checks: asStringList(a.checks),
    active_checks: asStringList(a.active_checks),
    iam_actions: asStringList(a.iam_actions),
    revertible: asBoolean(a.revertible),
    undo: asString(a.undo),
    in_enforced_scope: asBoolean(a.in_enforced_scope),
  };
};

const SETUP_STEP_IDS: readonly string[] = Object.values(REALTIME_SETUP_STEP);

/** The wizard's progress; unknown steps are dropped so a newer API cannot break it. */
export const toSetup = (
  document: RealtimeApiDocument | undefined,
): RealtimeSetupPayload | null => {
  const [resource] = resourcesOf(document);
  const payload = resource?.attributes?.payload;
  if (!isRecord(payload)) return null;
  const next = payload.next_step;
  return {
    activated: asBoolean(payload.activated),
    next_step: SETUP_STEP_IDS.includes(next as string)
      ? (next as RealtimeSetupStepId)
      : null,
    steps: asRecords(payload.steps)
      .filter((step) => SETUP_STEP_IDS.includes(step.id as string))
      .map((step) => ({
        id: step.id as RealtimeSetupStepId,
        required: asBoolean(step.required),
        done: asBoolean(step.done),
        detail: asNullableString(step.detail),
      })),
  };
};

export const toFramework = (
  resource: RealtimeApiResource,
): RealtimeFramework => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    name: asString(a.name, resource.id),
    version: asString(a.version),
  };
};

export const toFeed = (resource: RealtimeApiResource): RealtimeFeed => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    provider_id: relatedId(resource, "provider"),
    queue_url: asString(a.queue_url),
    region: asString(a.region, "us-east-1"),
    status: oneOf(
      a.status,
      Object.values(REALTIME_FEED_STATUS),
      REALTIME_FEED_STATUS.NOT_CONFIGURED,
    ),
    last_polled_at: asNullableString(a.last_polled_at),
    last_event_at: asNullableString(a.last_event_at),
    last_error: asString(a.last_error),
  };
};

export const toCredential = (
  resource: RealtimeApiResource,
): RealtimeCredential => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    provider_id: relatedId(resource, "provider"),
    role_arn: asString(a.role_arn),
    has_github_token: asBoolean(a.has_github_token),
  };
};

export const toDetection = (
  resource: RealtimeApiResource,
): RealtimeDetection => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    provider_id: relatedId(resource, "provider"),
    event_id: asString(a.event_id),
    event_time: asString(a.event_time),
    region: asString(a.region),
    rule_id: asString(a.rule_id),
    title: asString(a.title),
    severity: asString(a.severity),
    actor: asString(a.actor),
    resource: asString(a.resource),
    check_ids: asStringList(a.check_ids),
    requirements: asStringList(a.requirements),
    status: oneOf(
      a.status,
      Object.values(REALTIME_DETECTION_STATUS),
      REALTIME_DETECTION_STATUS.NEW,
    ),
    note: asString(a.note),
    verified_at: asNullableString(a.verified_at),
  };
};

export const toAction = (resource: RealtimeApiResource): RealtimeAction => {
  const a = resource.attributes ?? {};
  return {
    id: resource.id,
    provider_id: relatedId(resource, "provider"),
    detection_id: relatedId(resource, "detection") || null,
    kind: a.kind as RealtimeAction["kind"],
    status: a.status as RealtimeAction["status"],
    check_id: asString(a.check_id),
    resource_uid: asString(a.resource_uid),
    region: asString(a.region),
    severity: asString(a.severity),
    summary: asString(a.summary),
    pr_url: asString(a.pr_url),
    branch: asString(a.branch),
    revertible: asBoolean(a.revertible),
    inserted_at: asString(a.inserted_at),
  };
};

export const toEvent = (resource: RealtimeApiResource): RealtimeEvent => {
  const a = resource.attributes ?? {};
  return {
    // The API serialises the CloudTrail event id as the resource id.
    id: resource.id,
    event_time: asString(a.event_time),
    region: asString(a.region),
    event_source: asString(a.event_source),
    event_name: asString(a.event_name),
    user_type: asString(a.user_type),
    user_arn: asString(a.user_arn),
    source_ip: asString(a.source_ip),
    error_code: asString(a.error_code),
    read_only: asBoolean(a.read_only),
    provider_id: asString(a.provider_id),
    detection_status:
      (a.detection_status as RealtimeEvent["detection_status"]) ?? null,
    rule_id: asNullableString(a.rule_id),
  };
};

export const toHealth = (resource: RealtimeApiResource): RealtimeHealth => {
  const a = resource.attributes ?? {};
  return {
    enabled: asBoolean(a.enabled),
    clickhouse: oneOf(
      a.clickhouse,
      Object.values(REALTIME_DATA_STORE),
      REALTIME_DATA_STORE.UNAVAILABLE,
    ),
    events_last_hour: asNumber(a.events_last_hour),
    changes_last_hour: asNumber(a.changes_last_hour),
  };
};

/** One page of a JSON:API list, mapped through `map`. */
export const toPage = <T>(
  document: RealtimeApiDocument | undefined,
  map: (resource: RealtimeApiResource) => T,
): RealtimePage<T> => {
  const items = resourcesOf(document).map(map);
  const pagination = document?.meta?.pagination;
  return {
    items,
    page: pagination?.page ?? 1,
    pages: pagination?.pages ?? 1,
    count: pagination?.count ?? items.length,
  };
};

/**
 * The payload of a `realtime-insights` resource. Null when the document does not
 * carry one of the requested kind, so a panel shows its error state instead of
 * rendering a payload of the wrong shape.
 */
export const toInsightPayload = <K extends RealtimeInsightKind>(
  document: RealtimeApiDocument | undefined,
  kind: K,
): RealtimeInsightPayloads[K] | null => {
  const [resource] = resourcesOf(document);
  const attributes = resource?.attributes;
  if (!attributes || attributes.kind !== kind) return null;
  const payload = attributes.payload;
  if (!isRecord(payload)) return null;
  // The cost panel reads these during render; without them it would throw.
  if (
    kind === REALTIME_INSIGHT_KIND.COST &&
    payload.enabled === true &&
    !(
      isRecord(payload.total) &&
      Array.isArray(payload.series) &&
      Array.isArray(payload.anomalies)
    )
  ) {
    return null;
  }
  return payload as unknown as RealtimeInsightPayloads[K];
};

/**
 * Per-attribute messages of a 400, keyed by attribute name: the API points at
 * `/data/attributes/<name>` (or `/data/relationships/<name>`). Errors without
 * a pointer carry no field and are left to the generic message.
 */
export const toFieldErrors = (
  errors: RealtimeApiError[] | undefined,
): Record<string, string> => {
  const fieldErrors: Record<string, string> = {};
  (errors ?? []).forEach((error) => {
    const field = error.source?.pointer?.split("/").filter(Boolean).pop();
    if (field && field !== "data" && error.detail && !fieldErrors[field]) {
      fieldErrors[field] = error.detail;
    }
  });
  return fieldErrors;
};

/** JSON:API request body for a create or update. */
export const toRequestBody = ({
  type,
  attributes,
  id,
  providerId,
}: {
  type: string;
  attributes: Record<string, unknown>;
  id?: string;
  providerId?: string;
}) => ({
  data: {
    type,
    ...(id ? { id } : {}),
    attributes,
    ...(providerId
      ? {
          relationships: {
            provider: { data: { type: "providers", id: providerId } },
          },
        }
      : {}),
  },
});

/** A plain demo row dressed as the resource the real row mappers expect. */
const demoRowToResource = (
  row: Record<string, unknown>,
  index: number,
): RealtimeApiResource => ({
  id: asString(row.id, `demo-${index}`),
  type: "realtime-demo",
  attributes: row,
  relationships: {
    provider: asString(row.provider_id)
      ? { data: { id: asString(row.provider_id), type: "providers" } }
      : undefined,
    detection: asString(row.detection_id)
      ? { data: { id: asString(row.detection_id), type: "detections" } }
      : undefined,
  },
});

const DEMO_LIST_MAPPERS = {
  events: toEvent,
  detections: toDetection,
  actions: toAction,
} as const;

/**
 * The payload of a demo resource. The insight views have the real shape; the
 * lists carry their rows in `payload.items`. Null when the answer is not in
 * the expected shape, so a panel shows its error state, never a half view.
 */
export const toDemoPayload = <K extends RealtimeDemoKind>(
  document: RealtimeApiDocument | undefined,
  kind: K,
): RealtimeDemoPayloads[K] | null => {
  const [resource] = resourcesOf(document);
  const attributes = resource?.attributes;
  if (!attributes) return null;
  if (typeof attributes.kind === "string" && attributes.kind !== kind) {
    return null;
  }
  const payload = attributes.payload;
  if (!isRecord(payload)) return null;

  if (kind in DEMO_LIST_MAPPERS) {
    if (!Array.isArray(payload.items)) return null;
    const map = DEMO_LIST_MAPPERS[kind as keyof typeof DEMO_LIST_MAPPERS];
    const items = asRecords(payload.items).map((row, index) =>
      map(demoRowToResource(row, index)),
    );
    return {
      items,
      page: 1,
      pages: 1,
      count: items.length,
    } as unknown as RealtimeDemoPayloads[K];
  }
  return payload as unknown as RealtimeDemoPayloads[K];
};
