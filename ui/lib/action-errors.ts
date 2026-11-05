export const ACTION_ERROR_STATUS = {
  PAYMENT_REQUIRED: 402,
  FORBIDDEN: 403,
} as const;

export type ActionErrorStatus =
  (typeof ACTION_ERROR_STATUS)[keyof typeof ACTION_ERROR_STATUS];

// Shown whenever the API returns 402 for an over-limit (trial-expired) tenant.
// Rendered with a pricing link by the `UsageLimitMessage` component, and as
// plain text in toasts/field errors.
export const USAGE_LIMIT_MESSAGE =
  "You have exceeded the usage limit of one provider. You can add more providers and run unlimited scans by adding a subscription.";

export const ACTION_ERROR_MESSAGES = {
  [ACTION_ERROR_STATUS.PAYMENT_REQUIRED]: USAGE_LIMIT_MESSAGE,
  [ACTION_ERROR_STATUS.FORBIDDEN]:
    "You don't have permission to perform this action. Ask an administrator to update your role.",
} as const satisfies Record<ActionErrorStatus, string>;

export const ACTION_ERROR_API_MESSAGES = {
  [ACTION_ERROR_STATUS.PAYMENT_REQUIRED]:
    "An active subscription is required to use this API endpoint in Prowler Cloud.",
} as const satisfies Partial<Record<ActionErrorStatus, string>>;

export interface ActionErrorResult {
  error?: unknown;
  status?: number;
}

interface GetActionErrorMessageOptions {
  messages?: Partial<Record<ActionErrorStatus, string>>;
  fallback?: string;
}

export const isActionErrorStatus = (
  status: number | undefined,
): status is ActionErrorStatus =>
  status === ACTION_ERROR_STATUS.PAYMENT_REQUIRED ||
  status === ACTION_ERROR_STATUS.FORBIDDEN;

const isHttpErrorStatus = (status: number | undefined): boolean =>
  typeof status === "number" && status >= 400;

/** Form error `type` marking a usage-limit refusal, rendered with the plans link. */
export const USAGE_LIMIT_ERROR_TYPE = "usage_limit";

/** Thrown client-side when a usage-limit refusal must unwind a handler. */
export class UsageLimitError extends Error {
  constructor() {
    super(USAGE_LIMIT_MESSAGE);
    this.name = "UsageLimitError";
  }
}

/** The API refused the action because the tenant is over its plan's usage limit. */
export const isUsageLimitError = (
  result: ActionErrorResult | null | undefined,
): boolean => result?.status === ACTION_ERROR_STATUS.PAYMENT_REQUIRED;

/** Same check for one JSON:API error object, whose status is a string. */
export const isUsageLimitApiError = (error: { status?: string }): boolean =>
  error.status === String(ACTION_ERROR_STATUS.PAYMENT_REQUIRED);

export const hasActionError = (
  result: ActionErrorResult | null | undefined,
): result is ActionErrorResult =>
  result !== undefined &&
  result !== null &&
  ((result.error !== undefined && result.error !== null) ||
    isHttpErrorStatus(result.status));

export const getActionErrorMessage = (
  result: ActionErrorResult,
  options: GetActionErrorMessageOptions = {},
): string => {
  if (isActionErrorStatus(result.status)) {
    return (
      options.messages?.[result.status] ?? ACTION_ERROR_MESSAGES[result.status]
    );
  }

  if (result.error !== undefined && result.error !== null) {
    return String(result.error);
  }

  return options.fallback ?? "Oops! Something went wrong.";
};
