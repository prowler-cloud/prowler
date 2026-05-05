import {
  ALERT_ERROR_CODES,
  ALERT_SEEDING_WARNINGS,
  type AlertsActionError,
  type AlertsActionErrorSource,
  type AlertsActionResult,
  type AlertSeedingWarning,
  type AlertsErrorCode,
} from "../_types";

interface JsonApiErrorObject {
  status?: string | number;
  code?: string;
  detail?: string;
  source?: AlertsActionErrorSource;
  meta?: { code?: string; warnings?: string[] };
}

interface JsonApiErrorBody {
  errors?: JsonApiErrorObject[];
  detail?: string;
  message?: string;
  meta?: { warnings?: string[] };
}

const KNOWN_ERROR_CODES = new Set<string>(Object.values(ALERT_ERROR_CODES));
const KNOWN_WARNINGS = new Set<string>(Object.values(ALERT_SEEDING_WARNINGS));

const STATUS_FALLBACK_CODES: Record<number, AlertsErrorCode> = {
  401: ALERT_ERROR_CODES.FORBIDDEN,
  403: ALERT_ERROR_CODES.FORBIDDEN,
  404: ALERT_ERROR_CODES.NOT_FOUND,
  409: ALERT_ERROR_CODES.CONFLICT,
  429: ALERT_ERROR_CODES.THROTTLED,
};

const pickCode = (raw: string | undefined): AlertsErrorCode | undefined => {
  if (!raw) return undefined;
  return KNOWN_ERROR_CODES.has(raw) ? (raw as AlertsErrorCode) : undefined;
};

const pickWarning = (raw: string): AlertSeedingWarning | undefined =>
  KNOWN_WARNINGS.has(raw) ? (raw as AlertSeedingWarning) : undefined;

const collectWarnings = (
  body: JsonApiErrorBody | null,
): AlertSeedingWarning[] =>
  (body?.meta?.warnings ?? [])
    .map((w) => pickWarning(w))
    .filter((w): w is AlertSeedingWarning => w !== undefined);

const parseRetryAfter = (header: string | null): number | undefined => {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(header);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, Math.round((date - Date.now()) / 1000));
};

export const mapJsonApiErrorToAction = (
  status: number,
  body: JsonApiErrorBody | null,
  retryAfterHeader: string | null,
): AlertsActionError => {
  const firstError = body?.errors?.[0];
  const detail =
    firstError?.detail ||
    body?.detail ||
    body?.message ||
    "Custom alerts request failed.";
  const apiCode =
    pickCode(firstError?.code) ||
    pickCode(firstError?.meta?.code) ||
    pickCode((body as { code?: string } | null)?.code);
  const fallback = STATUS_FALLBACK_CODES[status] ?? ALERT_ERROR_CODES.UNKNOWN;
  const code: AlertsErrorCode = apiCode ?? fallback;
  const warnings = collectWarnings(body);
  return {
    code,
    detail,
    source: firstError?.source,
    status,
    retryAfterSeconds:
      code === ALERT_ERROR_CODES.THROTTLED
        ? parseRetryAfter(retryAfterHeader)
        : undefined,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
};

export const buildSuccessResult = <T>(
  data: T,
  body: JsonApiErrorBody | null,
): AlertsActionResult<T> => {
  const warnings = collectWarnings(body);
  return warnings.length > 0
    ? { ok: true, data, warnings }
    : { ok: true, data };
};

export const isThrottled = (
  result: AlertsActionResult<unknown>,
): result is { ok: false; error: AlertsActionError } =>
  !result.ok && result.error.code === ALERT_ERROR_CODES.THROTTLED;

export const buildUnexpectedError = (
  detail = "Unexpected error.",
): AlertsActionError => ({
  code: ALERT_ERROR_CODES.UNKNOWN,
  detail,
});
