import { AlertCircle, CheckCircle2, RefreshCw } from "lucide-react";

import {
  FEEDBACK_VARIANT,
  type FeedbackState,
} from "@/app/(prowler)/lighthouse/_lib/config";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";

export function ConfigFeedbackAlert({
  feedback,
  onClose,
  onRefreshStatus,
}: {
  feedback: FeedbackState;
  onClose: () => void;
  onRefreshStatus: () => void;
}) {
  const Icon =
    feedback.variant === FEEDBACK_VARIANT.ERROR
      ? AlertCircle
      : feedback.variant === FEEDBACK_VARIANT.SUCCESS
        ? CheckCircle2
        : RefreshCw;

  return (
    <Alert variant={feedback.variant} onClose={onClose}>
      <Icon className="size-4" />
      <AlertTitle>{feedback.title}</AlertTitle>
      <AlertDescription>
        {feedback.description && <p>{feedback.description}</p>}
        {feedback.showRefreshStatus && (
          <Button
            type="button"
            variant="link"
            size="link-sm"
            className="h-auto p-0"
            onClick={onRefreshStatus}
          >
            <RefreshCw className="size-3.5" />
            Refresh status
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}
