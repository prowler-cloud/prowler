import { failureCopy } from "@/app/(prowler)/realtime/_lib/display";
import type { RealtimeFailure } from "@/app/(prowler)/realtime/_types";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn";

interface RealtimePanelErrorProps {
  failure: Pick<RealtimeFailure, "status" | "error">;
}

/** Why one panel could not load. The rest of the page keeps working. */
export function RealtimePanelError({ failure }: RealtimePanelErrorProps) {
  const copy = failureCopy(failure.status);
  return (
    <Alert variant={failure.status === 503 ? "info" : "error"}>
      <AlertTitle>{copy.title}</AlertTitle>
      <AlertDescription>
        {failure.status === 0 || failure.status >= 500
          ? failure.error
          : copy.description}
      </AlertDescription>
    </Alert>
  );
}
