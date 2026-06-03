"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  getOrderedFlows,
  type OnboardingFlow,
  shouldStartOnboarding,
} from "@/lib/onboarding";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import { TOUR_COMPLETION_STATES } from "@/lib/tours/tour-types";

import { OnboardingWelcomeModal } from "./onboarding-welcome-modal";

interface OnboardingGateProps {
  // Tri-state: `true`/`false` from a successful provider fetch, `undefined`
  // when the layout could not determine provider state (failed/ambiguous
  // fetch). `undefined` must fail open — never force the modal on an unknown
  // state.
  hasProviders?: boolean;
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
    // The mandatory gate ONLY ever forces the FIRST ordered flow (the new-user
    // entry point, `add-provider`). The remaining sequence flows
    // (view-first-scan, explore-findings, view-compliance, ...) are reached via
    // the post-connect checkpoint and the avatar replay list — never the gate.
    // Walking to the "first INCOMPLETE flow" would wrongly surface a later
    // flow's modal once add-provider is dismissed but its successors have no
    // record yet, so the gate is scoped to the first ordered flow alone.
    const flow = getOrderedFlows()[0];
    if (!flow) {
      setActiveFlow(null);
      return;
    }

    // `shouldStartOnboarding` receives the RAW (possibly `undefined`)
    // `hasProviders` and applies the strict `=== false` fail-open guard, so an
    // ambiguous provider state never forces the modal. A completion/dismissal
    // record for the gate flow also keeps the gate silent.
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
