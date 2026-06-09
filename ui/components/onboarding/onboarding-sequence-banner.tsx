"use client";

import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { getSequenceProgress } from "./onboarding-sequence-banner.logic";

interface OnboardingSequenceBannerProps {
  // Defaults to true (fail-open) when scan state is unknown, so the banner never
  // wrongly blocks progression.
  hasCompletedScan?: boolean;
}

// Non-blocking bottom banner for an active sequence. Owns advance/exit; the per-route
// tour only shows on arrival and no longer auto-advances on close.
export function OnboardingSequenceBanner({
  hasCompletedScan = true,
}: OnboardingSequenceBannerProps = {}) {
  const router = useRouter();
  const active = useOnboardingSequenceStore((state) => state.active);
  const currentFlowId = useOnboardingSequenceStore(
    (state) => state.currentFlowId,
  );

  const progress = getSequenceProgress(currentFlowId);
  if (!active || !progress) return null;

  const { index, total, flow, nextFlow } = progress;

  // Block advancing into a scan-dependent step (e.g. findings, compliance) until a
  // scan has finished — those steps have no data to show otherwise.
  const continueDisabled =
    hasCompletedScan === false && Boolean(nextFlow?.dataRequirementHint);
  // Only surface a hint to explain why Continue is disabled. The gate already
  // guarantees scan-dependent steps are reached with data, so showing a step's
  // own "wait for findings" hint once we're there would be stale/misleading.
  const hint = continueDisabled ? nextFlow?.dataRequirementHint : undefined;

  const handleContinue = () => {
    if (continueDisabled) return;
    const sequence = useOnboardingSequenceStore.getState();
    if (!nextFlow) {
      sequence.stop(); // last step — end in place
      return;
    }
    sequence.advance();
    router.push(nextFlow.route);
  };

  const handleExit = () => {
    useOnboardingSequenceStore.getState().stop();
  };

  return (
    <div
      role="region"
      aria-label="Onboarding tour progress"
      className={cn(
        "fixed inset-x-0 bottom-0 z-40",
        "border-border-neutral-secondary bg-bg-neutral-secondary border-t",
        "px-4 py-3 shadow-lg",
      )}
    >
      {/* Everything aligned to the right edge: step text first, then the two buttons.
          No max-width/centering — that left a gap between the content and the screen. */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-end sm:gap-6">
        <div className="flex flex-col gap-1 sm:text-right">
          {/* Polite live region: screen readers announce step transitions. */}
          <p
            role="status"
            aria-live="polite"
            className="text-text-neutral-primary text-sm font-medium"
          >
            Step {index + 1} of {total}: {flow.title}
          </p>
          {hint ? (
            <p className="text-text-warning-primary text-xs">{hint}</p>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {/* Secondary action: skips the whole tour. Outline matches the app's modal Cancel variant. */}
          <Button variant="outline" size="sm" onClick={handleExit}>
            Skip
          </Button>
          <Button
            variant="default"
            size="sm"
            disabled={continueDisabled}
            onClick={handleContinue}
          >
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
}
