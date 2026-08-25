/**
 * One error object from a JSON:API error body. `detail` is not guaranteed: the
 * organization endpoints put the message under the offending field's own key and
 * let the pointer stop at the containing attribute —
 * `{"service_account_key": "…", "source": {"pointer": "/data/attributes/secret"}}`.
 */
export interface ApiErrorObject {
  detail?: string;
  source?: { pointer?: string };
  code?: string;
  status?: string;
  [field: string]: unknown;
}

interface ErrorResult {
  error?: string;
  errors?: ApiErrorObject[];
}

/** Keys carrying error metadata rather than a field's message. */
const ERROR_META_KEYS = new Set([
  "detail",
  "source",
  "code",
  "status",
  "title",
]);

function humanizeFieldName(field: string): string {
  const words = field.replace(/_/g, " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function findFieldMessage(
  error: ApiErrorObject,
): { field: string; message: string } | null {
  for (const [field, value] of Object.entries(error)) {
    if (ERROR_META_KEYS.has(field)) continue;
    if (typeof value === "string" && value.trim()) {
      return { field, message: value.trim() };
    }
  }

  return null;
}

/**
 * Readable text for a single server error: `detail` when present, otherwise the
 * field-keyed message prefixed with its field — in that shape the key is the only
 * thing naming the input the message is about.
 */
export function describeApiError(error: ApiErrorObject): string | null {
  if (typeof error.detail === "string" && error.detail.trim()) {
    return error.detail.trim();
  }

  const fieldMessage = findFieldMessage(error);
  if (!fieldMessage) {
    return null;
  }

  return `${humanizeFieldName(fieldMessage.field)}: ${fieldMessage.message}`;
}

/**
 * The field names an error mentions — pointer segments plus its own keys — so a
 * form field matches whichever of the two shapes the error arrived in.
 */
export function apiErrorFieldNames(error: ApiErrorObject): string {
  const pointer = error.source?.pointer ?? "";
  const keys = Object.keys(error).filter((key) => !ERROR_META_KEYS.has(key));

  return `${pointer} ${keys.join(" ")}`;
}

export function extractErrorMessage(
  response: unknown,
  fallback: string,
): string {
  if (!response || typeof response !== "object") {
    return fallback;
  }

  const responseRecord = response as ErrorResult;
  const firstError = responseRecord.errors?.[0];
  const detailedError = firstError ? describeApiError(firstError) : null;

  return detailedError || responseRecord.error || fallback;
}
