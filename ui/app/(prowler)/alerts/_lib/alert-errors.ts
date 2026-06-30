import {
  ACTION_ERROR_STATUS,
  getActionErrorMessage,
} from "@/lib/action-errors";

export const ALERTS_PERMISSION_ERROR =
  "You don't have permission to manage alerts. Ask an administrator to update your role.";

interface AlertActionErrorResult {
  error: string;
  status?: number;
}

export const getAlertMutationError = (
  result: AlertActionErrorResult,
  fallback = result.error,
): string =>
  getActionErrorMessage(
    { ...result, error: fallback },
    {
      messages: {
        [ACTION_ERROR_STATUS.FORBIDDEN]: ALERTS_PERMISSION_ERROR,
      },
    },
  );
