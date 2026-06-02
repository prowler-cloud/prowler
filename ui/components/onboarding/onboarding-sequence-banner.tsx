"use client";

import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { getSequenceProgress } from "./onboarding-sequence-banner.logic";

// Persistent, NON-blocking bottom banner shown while a guided sequence is
// active. Unlike a Dialog it never traps focus or covers the page, so the user
// can perform the step's real action (e.g. launch a scan) at their own pace and
// then click Continue. The banner owns sequence advance/exit; the per-route
// tour only shows on arrival and no longer auto-advances on close.
export function OnboardingSequenceBanner() {
  const router = useRouter();
  const active = useOnboardingSequenceStore((state) => state.active);
  const currentFlowId = useOnboardingSequenceStore(
    (state) => state.currentFlowId,
  );

  // Self-hide: render nothing unless an active sequence resolves to a known
  // flow. Derived entirely from the registry — no hardcoded flow list.
  const progress = getSequenceProgress(currentFlowId);
  if (!active || !progress) return null;

  const { index, total, flow, nextFlow } = progress;

  const handleContinue = () => {
    const sequence = useOnboardingSequenceStore.getState();
    if (!nextFlow) {
      // Last step: end the sequence in place, no navigation.
      sequence.stop();
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
      <div className="mx-auto flex max-w-5xl flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1">
          <p className="text-text-neutral-primary text-sm font-medium">
            Step {index + 1} of {total}: {flow.title}
          </p>
          {flow.dataRequirementHint ? (
            <p className="text-text-warning text-xs">
              {flow.dataRequirementHint}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleExit}>
            Exit
          </Button>
          <Button variant="default" size="sm" onClick={handleContinue}>
            Continue
          </Button>
        </div>
      </div>
    </div>
  );
}
