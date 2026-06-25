const SENTRY_EVENT_LEVEL = {
  WARNING: "warning",
} as const;

export const SENTRY_EVENT_SOURCE = {
  CLIENT: "client",
  EDGE: "edge",
  SERVER: "server",
  SERVER_ACTION: "server_action",
} as const;

const SENTRY_EVENT_KIND = {
  API: "api",
  RUNTIME: "runtime",
} as const;

const SENTRY_ACTIONABILITY = {
  ACTIONABLE: "actionable",
} as const;

const EXPECTED_CONTROL_FLOW_MESSAGES = [
  "NEXT_REDIRECT",
  "NEXT_NOT_FOUND",
  "AbortError",
  "ResizeObserver",
] as const;

const HTTP_CONTEXT_MESSAGES = [
  /\bapi\b/i,
  /\bfetch\b/i,
  /\bhttp\b/i,
  /\brequest failed\b/i,
] as const;

const EXPECTED_HTTP_STATUS_CODES = new Set([401, 403, 404]);
const EXPECTED_HTTP_STATUS_PATTERN = /(^|\D)(401|403|404)(\D|$)/;
const REPORTED_ERROR_MARKER = Symbol.for("prowler.sentry.reported_error");
const reportedErrors = new WeakSet<object>();

type SentryEventSource =
  (typeof SENTRY_EVENT_SOURCE)[keyof typeof SENTRY_EVENT_SOURCE];
type SentryPolicyTagValue = string | number | boolean | null | undefined;

export interface SentryEventPolicyOptions {
  source?: SentryEventSource;
}

export interface SentryEventHint {
  originalException?: unknown;
}

export interface SentryPolicyEvent {
  tags?: Record<string, SentryPolicyTagValue>;
}

type ObjectRecord = Record<PropertyKey, unknown>;
type ReportedErrorRecord = Record<symbol, unknown>;

export function applySentryEventPolicy<TEvent extends object>(
  event: TEvent,
  hint?: SentryEventHint,
  options: SentryEventPolicyOptions = {},
) {
  if (shouldDropSentryEvent(event, hint)) {
    return null;
  }

  tagActionableEvent(event, options);

  return event;
}

export function markErrorAsReported(error: unknown) {
  if (!isObjectLike(error)) {
    return;
  }

  reportedErrors.add(error);

  try {
    Object.defineProperty(error, REPORTED_ERROR_MARKER, {
      configurable: false,
      enumerable: false,
      value: true,
    });
  } catch {
    // WeakSet fallback still suppresses duplicates for non-extensible objects.
  }
}

export function isErrorAlreadyReported(error: unknown) {
  if (!isObjectLike(error)) {
    return false;
  }

  return (
    reportedErrors.has(error) ||
    (error as ReportedErrorRecord)[REPORTED_ERROR_MARKER] === true
  );
}

function shouldDropSentryEvent(event: object, hint?: SentryEventHint) {
  if (getStringProperty(event, "level") === SENTRY_EVENT_LEVEL.WARNING) {
    return true;
  }

  if (isErrorAlreadyReported(hint?.originalException)) {
    return true;
  }

  const messages = getEventMessages(event, hint);

  if (hasExpectedControlFlowMessage(messages)) {
    return true;
  }

  return hasExpectedHttpStatus(event, hint?.originalException, messages);
}

function tagActionableEvent(event: object, options: SentryEventPolicyOptions) {
  const mutableEvent = event as SentryPolicyEvent;

  mutableEvent.tags = {
    ...mutableEvent.tags,
    actionability: SENTRY_ACTIONABILITY.ACTIONABLE,
    kind: inferEventKind(event),
    ...(options.source ? { source: options.source } : {}),
  };
}

function inferEventKind(event: object) {
  const tags = getRecordProperty(event, "tags");
  const errorType = getStringProperty(tags, "error_type");
  const apiError = getProperty(tags, "api_error");

  if (
    errorType === "api_error" ||
    apiError === true ||
    getStatusFromTags(tags)
  ) {
    return SENTRY_EVENT_KIND.API;
  }

  return SENTRY_EVENT_KIND.RUNTIME;
}

function hasExpectedControlFlowMessage(messages: string[]) {
  return EXPECTED_CONTROL_FLOW_MESSAGES.some((expectedMessage) =>
    messages.some((message) => message.includes(expectedMessage)),
  );
}

function hasExpectedHttpStatus(
  event: object,
  originalException: unknown,
  messages: string[],
) {
  const tags = getRecordProperty(event, "tags");
  const statusFromTags = getStatusFromTags(tags);
  const statusFromError = getStatusFromError(originalException);

  if (
    (statusFromTags && EXPECTED_HTTP_STATUS_CODES.has(statusFromTags)) ||
    (statusFromError && EXPECTED_HTTP_STATUS_CODES.has(statusFromError))
  ) {
    return true;
  }

  return (
    hasExpectedHttpStatusMessage(messages) &&
    hasApiOrHttpContext(event, messages)
  );
}

function hasExpectedHttpStatusMessage(messages: string[]) {
  return messages.some((message) => EXPECTED_HTTP_STATUS_PATTERN.test(message));
}

function hasApiOrHttpContext(event: object, messages: string[]) {
  const tags = getRecordProperty(event, "tags");

  return hasApiTags(tags) || hasHttpContextMessage(messages);
}

function hasApiTags(tags: unknown) {
  return (
    getStringProperty(tags, "error_type") === "api_error" ||
    getProperty(tags, "api_error") === true
  );
}

function hasHttpContextMessage(messages: string[]) {
  return messages.some((message) =>
    HTTP_CONTEXT_MESSAGES.some((pattern) => pattern.test(message)),
  );
}

function getStatusFromTags(tags: unknown) {
  return (
    normalizeStatusCode(getProperty(tags, "status_code")) ??
    normalizeStatusCode(getProperty(tags, "status")) ??
    normalizeStatusCode(getProperty(tags, "http.status_code"))
  );
}

function getStatusFromError(error: unknown): number | undefined {
  const response = getRecordProperty(error, "response");

  return (
    normalizeStatusCode(getProperty(error, "status")) ??
    normalizeStatusCode(getProperty(error, "statusCode")) ??
    normalizeStatusCode(getProperty(error, "status_code")) ??
    normalizeStatusCode(getProperty(response, "status"))
  );
}

function getEventMessages(event: object, hint?: SentryEventHint) {
  return [
    getStringProperty(event, "message"),
    ...getExceptionMessages(event),
    getStringProperty(hint?.originalException, "name"),
    getStringProperty(hint?.originalException, "message"),
    typeof hint?.originalException === "string"
      ? hint.originalException
      : undefined,
  ].filter(isString);
}

function getExceptionMessages(event: object) {
  const exception = getRecordProperty(event, "exception");
  const values = getProperty(exception, "values");

  if (!Array.isArray(values)) {
    return [];
  }

  return values.flatMap((value) => [
    getStringProperty(value, "type"),
    getStringProperty(value, "value"),
  ]);
}

function normalizeStatusCode(value: unknown) {
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }

  if (typeof value === "string" && /^\d{3}$/.test(value)) {
    return Number(value);
  }

  return undefined;
}

function getStringProperty(value: unknown, property: string) {
  const propertyValue = getProperty(value, property);

  return typeof propertyValue === "string" ? propertyValue : undefined;
}

function getRecordProperty(value: unknown, property: string) {
  const propertyValue = getProperty(value, property);

  return isRecord(propertyValue) ? propertyValue : undefined;
}

function getProperty(value: unknown, property: string) {
  return isRecord(value) ? value[property] : undefined;
}

function isRecord(value: unknown): value is ObjectRecord {
  return typeof value === "object" && value !== null;
}

function isObjectLike(value: unknown): value is object {
  return (
    (typeof value === "object" && value !== null) || typeof value === "function"
  );
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}
