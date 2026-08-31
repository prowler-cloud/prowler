"use client";

import { Check, CircleAlert, Loader2, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export const CHECK_STATUS = {
  /** No check has run against the channels currently on record. */
  IDLE: "idle",
  RUNNING: "running",
  PASSED: "passed",
  FAILED: "failed",
} as const;

export type CheckStatus = (typeof CHECK_STATUS)[keyof typeof CHECK_STATUS];

interface CheckStatusStyle {
  /** `null` for the resting state, which shows no outcome to decorate. */
  icon: LucideIcon | null;
  className: string;
}

const CHECK_STATUS_STYLES = {
  [CHECK_STATUS.IDLE]: {
    icon: null,
    className: "",
  },
  [CHECK_STATUS.RUNNING]: {
    icon: Loader2,
    className:
      "border-border-neutral-secondary bg-bg-neutral-tertiary text-text-neutral-secondary",
  },
  // The dark pass tokens are sized for a whole card, and at this width they
  // read as an alert rather than a note, so they are taken down a shade there.
  [CHECK_STATUS.PASSED]: {
    icon: Check,
    className:
      "border-bg-pass bg-bg-pass-secondary text-text-success-primary dark:border-bg-pass/40 dark:bg-bg-pass-secondary/40",
  },
  [CHECK_STATUS.FAILED]: {
    icon: CircleAlert,
    className:
      "border-border-error bg-bg-fail-secondary text-text-error-primary dark:border-border-error/50",
  },
} as const satisfies Record<CheckStatus, CheckStatusStyle>;

interface SlackConnectionCheckStatusProps {
  status: CheckStatus;
  /** What the last check found. Absent while no check covers the record. */
  outcome?: ReactNode;
  /**
   * Id the control points at with `aria-describedby`. The caption alone carries
   * it: an outcome read out as the control's description would say what the
   * last check did, where the description has to say what pressing it does.
   */
  captionId: string;
  /** What the check does, or why it cannot run. */
  children: ReactNode;
}

/**
 * The connection check's standing state: what a check last found, over the
 * caption explaining what running one does.
 *
 * The two are kept in separate registers — the outcome boxed, the caption plain
 * underneath — because they are answers to different questions and can honestly
 * disagree. A refused channel is still a channel the next check will try, so
 * reading the caption as a continuation of the outcome ("Slack refused #ops" …
 * "posts the confirmation to #ops") would turn a true pair of statements into a
 * contradiction.
 */
export const SlackConnectionCheckStatus = ({
  status,
  outcome,
  captionId,
  children,
}: SlackConnectionCheckStatusProps) => {
  const { icon: Icon, className } = CHECK_STATUS_STYLES[status];

  return (
    <div className={cn("flex w-full flex-col", outcome && "gap-2")}>
      <div
        className={cn(
          "flex items-start gap-2 text-xs",
          outcome && "rounded-lg border px-3 py-2",
          outcome && className,
        )}
      >
        {Icon && outcome && (
          <Icon
            aria-hidden="true"
            className={cn(
              "mt-0.5 size-3.5 shrink-0",
              status === CHECK_STATUS.RUNNING && "animate-spin",
            )}
          />
        )}
        {/* Always mounted, so a landing outcome is announced as a change to a
            region that was already there — and polite, since the user asked
            for the check and is watching it. Empty, it takes no room. */}
        <p
          aria-live="polite"
          className={cn("font-medium", !outcome && "sr-only")}
        >
          {outcome}
        </p>
      </div>
      <p
        id={captionId}
        className="text-text-neutral-tertiary max-w-prose text-xs"
      >
        {children}
      </p>
    </div>
  );
};
