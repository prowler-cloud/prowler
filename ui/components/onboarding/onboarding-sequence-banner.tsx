"use client";

import { useRouter } from "next/navigation";

import { Button } from "@/components/shadcn";
import { getFlowById } from "@/lib/onboarding";
import { cn } from "@/lib/utils";
import { useOnboardingSequenceStore } from "@/store/onboarding-sequence";

import { getSequenceProgress } from "./onboarding-sequence-banner.logic";

// Target for the "Run a scan" shortcut; the scans page trigger re-runs its tour on arrival.
const SCAN_FLOW_ID = "view-first-scan";

interface OnboardingSequenceBannerProps {
  // Defaults to true (fail-open) when scan state is unknown.
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

  // Shortcut only on a data-gated step that still lacks scan data, not on the scan step itself.
  const scanFlow = getFlowById(SCAN_FLOW_ID);
  const showScanShortcut =
    Boolean(flow.dataRequirementHint) &&
    hasCompletedScan === false &&
    flow.id !== SCAN_FLOW_ID &&
    scanFlow !== undefined;

  const handleRunScan = () => {
    if (!scanFlow) return;
    useOnboardingSequenceStore.getState().goToFlow(scanFlow.id);
    router.push(scanFlow.route);
  };

  const handleContinue = () => {
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
      <div className="mx-auto flex max-w-5xl flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1">
          {/* Polite live region: screen readers announce step transitions. */}
          <p
            role="status"
            aria-live="polite"
            className="text-text-neutral-primary text-sm font-medium"
          >
            Step {index + 1} of {total}: {flow.title}
          </p>
          {flow.dataRequirementHint ? (
            <p className="text-text-warning-primary text-xs">
              {flow.dataRequirementHint}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {showScanShortcut ? (
            <Button variant="outline" size="sm" onClick={handleRunScan}>
              Run a scan
            </Button>
          ) : null}
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
