import { ReactNode } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Button } from "@/components/shadcn/button/button";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { failureCopy } from "@/lib/realtime/display";
import type { RealtimeFailure } from "@/types/realtime";

export function PanelLoading({ label = "Loading" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={label}
      className="flex flex-col gap-3"
    >
      <Skeleton className="h-6 w-1/3" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-24 w-full" />
      <span className="sr-only">{label}…</span>
    </div>
  );
}

/**
 * 403, 404 and 503 are expected answers (no access, feature off, no data
 * store) and read as notices; anything else is an error with a retry.
 */
export function PanelFailure({
  failure,
  onRetry,
  subject,
}: {
  failure: RealtimeFailure;
  onRetry?: () => void;
  /** Used in the generic error title, e.g. "the event stream". */
  subject?: string;
}) {
  const copy = failureCopy(failure.status);
  const isNotice = [403, 404, 503].includes(failure.status);
  const title = !isNotice && subject ? `Could not load ${subject}` : copy.title;
  return (
    <Alert variant={isNotice ? "info" : "error"}>
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <p>{isNotice ? copy.description : failure.error || copy.description}</p>
        {onRetry && failure.status !== 404 && (
          <Button variant="outline" size="sm" onClick={onRetry}>
            Retry
          </Button>
        )}
      </AlertDescription>
    </Alert>
  );
}

export function PanelEmpty({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <div className="border-border-neutral-secondary flex flex-col items-start gap-2 rounded-xl border border-dashed p-6">
      <p className="text-text-neutral-primary text-sm font-medium">{title}</p>
      {description && (
        <p className="text-text-neutral-tertiary max-w-prose text-sm">
          {description}
        </p>
      )}
      {children}
    </div>
  );
}
