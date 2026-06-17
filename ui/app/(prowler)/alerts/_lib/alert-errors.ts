export const ALERTS_PERMISSION_ERROR =
  "You don't have permission to manage alerts. Ask an administrator to update your role.";

interface AlertActionErrorResult {
  error: string;
  status?: number;
}

export const getAlertMutationError = (
  result: AlertActionErrorResult,
): string => (result.status === 403 ? ALERTS_PERMISSION_ERROR : result.error);
