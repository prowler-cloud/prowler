import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { UsageLimitMessage } from "@/components/shared/usage-limit-message";
import {
  ACTION_ERROR_STATUS,
  type ActionErrorResult,
  getActionErrorMessage,
} from "@/lib/action-errors";

import { CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE } from "../_types";

interface CrossProviderErrorAlertProps {
  result?: ActionErrorResult;
  message?: string;
}

export const CrossProviderErrorAlert = ({
  result,
  message = CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE,
}: CrossProviderErrorAlertProps) => {
  const isUsageLimit = result?.status === ACTION_ERROR_STATUS.PAYMENT_REQUIRED;

  return (
    <Alert variant="error">
      <AlertTriangle className="size-4" />
      <AlertDescription>
        {isUsageLimit ? (
          <UsageLimitMessage />
        ) : result ? (
          getActionErrorMessage(result, { fallback: message })
        ) : (
          message
        )}
      </AlertDescription>
    </Alert>
  );
};
