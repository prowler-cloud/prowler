"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  getFirstIncompleteFlow,
  type OnboardingFlow,
  shouldStartOnboarding,
} from "@/lib/onboarding";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import { TOUR_COMPLETION_STATES } from "@/lib/tours/tour-types";

import { OnboardingWelcomeModal } from "./onboarding-welcome-modal";

interface OnboardingGateProps {
  hasProviders: boolean;
}

// Mandatory new-user gate. Mounted once in the (prowler) layout. Reads the
// already-hydrated `hasProviders` signal plus the per-tour localStorage record
// to decide whether to force a new user into the Welcome modal. All decision
// logic runs inside `useEffect` (client-only) so the server renders nothing and
// there is no hydration mismatch.
export function OnboardingGate({ hasProviders }: OnboardingGateProps) {
  const router = useRouter();
  const [activeFlow, setActiveFlow] = useState<OnboardingFlow | null>(null);

  useEffect(() => {
    // Select the first flow that is incomplete by account state and has no
    // browser record. `getFirstIncompleteFlow` uses `isComplete(ctx)` which
    // false-positives when `hasProviders` is undefined, so it is NOT the final
    // authority — `shouldStartOnboarding` below applies the strict `=== false`
    // fail-open guard.
    const flow = getFirstIncompleteFlow({ hasProviders }, localStorageAdapter);
    if (!flow) {
      setActiveFlow(null);
      return;
    }

    const completionRecord = localStorageAdapter.get(flow.tour);
    if (shouldStartOnboarding({ hasProviders, completionRecord })) {
      setActiveFlow(flow);
    } else {
      setActiveFlow(null);
    }
  }, [hasProviders]);

  if (!activeFlow) return null;

  const handleAccept = () => {
    // Hand off via the URL; the providers page's trigger starts the tour. No
    // record is written here — completion is persisted only when the tour
    // finishes or is skipped.
    setActiveFlow(null);
    router.push(`${activeFlow.route}?onboarding=${activeFlow.id}`);
  };

  const handleDismiss = () => {
    // Persist a dismissal so the gate stops re-prompting in this browser.
    localStorageAdapter.set(
      { id: activeFlow.tour.id, version: activeFlow.tour.version },
      {
        tourId: activeFlow.tour.id,
        version: activeFlow.tour.version,
        state: TOUR_COMPLETION_STATES.DISMISSED,
        completedAt: new Date().toISOString(),
      },
    );
    setActiveFlow(null);
  };

  return (
    <OnboardingWelcomeModal
      open
      flowTitle={activeFlow.title}
      flowDescription={activeFlow.description}
      onAccept={handleAccept}
      onDismiss={handleDismiss}
    />
  );
}
