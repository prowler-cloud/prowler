export const ACTION_ERROR_STATUS = {
  PAYMENT_REQUIRED: 402,
  FORBIDDEN: 403,
} as const;

export type ActionErrorStatus =
  (typeof ACTION_ERROR_STATUS)[keyof typeof ACTION_ERROR_STATUS];

// Shown whenever the API returns 402 for an over-limit (trial-expired) tenant.
// Rendered with a billing link by he `UsageLimitMessage` component, and as
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

const isActionErrorStatus = (
  status: number | undefined,
): status is ActionErrorStatus =>
  status === ACTION_ERROR_STATUS.PAYMENT_REQUIRED ||
  status === ACTION_ERROR_STATUS.FORBIDDEN;

const isHttpErrorStatus = (status: number | undefined): boolean =>
  typeof status === "number" && status >= 400;

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
