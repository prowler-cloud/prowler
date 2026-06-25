import { AlertCircle, CheckCircle2, Info } from "lucide-react";

import {
  FEEDBACK_VARIANT,
  type FeedbackState,
} from "@/app/(prowler)/lighthouse/_lib/config";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";

export function ConfigFeedbackAlert({
  feedback,
  onClose,
}: {
  feedback: FeedbackState;
  onClose: () => void;
}) {
  const Icon =
    feedback.variant === FEEDBACK_VARIANT.ERROR
      ? AlertCircle
      : feedback.variant === FEEDBACK_VARIANT.SUCCESS
        ? CheckCircle2
        : Info;

  return (
    <Alert variant={feedback.variant} onClose={onClose}>
      <Icon className="size-4" />
      <AlertTitle>{feedback.title}</AlertTitle>
      <AlertDescription>
        {feedback.description && <p>{feedback.description}</p>}
      </AlertDescription>
    </Alert>
  );
}
