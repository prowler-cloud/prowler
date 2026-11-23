"use client";

import { CircleAlert, Loader2 } from "lucide-react";
import { useEffect, useRef } from "react";

import { ConnectionPending } from "@/components/icons";

interface ConnectionFeedbackProps {
  isTesting: boolean;
  error: string | null;
  pending: string | null;
}

/**
 * Progress line while the test runs, the neutral message once the wait is
 * exhausted with no verdict, or the API's reason once it is refused.
 */
export function ConnectionFeedback({
  isTesting,
  error,
  pending,
}: ConnectionFeedbackProps) {
  const alertRef = useRef<HTMLDivElement>(null);

  // The form scrolls inside the modal and the action button sits outside it, so
  // an error or a pending result raised from the footer can land above the fold.
  useEffect(() => {
    if (!error && !pending) return;
    // Guarded: jsdom has no scrollIntoView, and a throw here would unmount the step.
    alertRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }, [error, pending]);

  if (isTesting) {
    return (
      <p
        role="status"
        className="text-text-neutral-secondary flex items-center gap-2 text-sm"
      >
        <Loader2 aria-hidden className="size-4 animate-spin" />
        Testing the connection. This usually takes a few seconds.
      </p>
    );
  }

  if (pending) {
    return (
      <div
        ref={alertRef}
        role="status"
        data-testid="connection-pending"
        className="bg-bg-warning-secondary border-border-neutral-secondary flex items-start gap-3 rounded-lg border p-4"
      >
        <ConnectionPending
          size={20}
          aria-hidden="true"
          className="text-text-warning-primary shrink-0"
        />
        <p className="text-text-warning-primary min-w-0 text-sm break-words">
          {pending}
        </p>
      </div>
    );
  }

  if (!error) return null;

  return (
    <div
      ref={alertRef}
      role="alert"
      data-testid="connection-error"
      className="border-border-error flex items-start gap-3 rounded-lg border p-4"
    >
      <CircleAlert
        aria-hidden
        className="text-text-error-primary size-5 shrink-0"
      />
      <p className="text-text-error-primary min-w-0 text-sm break-words">
        {error}
      </p>
    </div>
  );
}
