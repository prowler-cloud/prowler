export const ACTION_ERROR_STATUS = {
  PAYMENT_REQUIRED: 402,
  FORBIDDEN: 403,
} as const;

export type ActionErrorStatus =
  (typeof ACTION_ERROR_STATUS)[keyof typeof ACTION_ERROR_STATUS];

export const ACTION_ERROR_MESSAGES = {
  [ACTION_ERROR_STATUS.PAYMENT_REQUIRED]:
    "Your subscription doesn't allow this action. Upgrade your plan or contact an administrator.",
  [ACTION_ERROR_STATUS.FORBIDDEN]:
    "You don't have permission to perform this action. Ask an administrator to update your role.",
} as const satisfies Record<ActionErrorStatus, string>;

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
