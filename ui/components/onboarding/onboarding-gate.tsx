"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { getOrderedFlows, shouldStartOnboarding } from "@/lib/onboarding";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import { TOUR_COMPLETION_STATES } from "@/lib/tours/tour-types";
import { useTourCompletion } from "@/lib/tours/use-tour-completion";
import { useOnboardingCheckpointStore } from "@/store/onboarding-checkpoint";

import { OnboardingWelcomeModal } from "./onboarding-welcome-modal";

interface OnboardingGateProps {
  // `undefined` = fetch failed/ambiguous; fail-open (never force the modal).
  hasProviders?: boolean;
}

// Mandatory new-user gate. Mounted once in the layout; decision derived during render
// via useSyncExternalStore — server renders nothing, no hydration mismatch.
export function OnboardingGate({ hasProviders }: OnboardingGateProps) {
  const router = useRouter();

  // Gate forces only the first flow (`add-provider`); remaining flows come via checkpoint/replay.
  const flow = getOrderedFlows()[0] ?? null;

  // Returns null on server/first render — gate stays closed until resolved client-side.
  const completionRecord = useTourCompletion(flow?.tour ?? null);

  // Session flag prevents the gate re-opening after accept/dismiss within this mount.
  const [resolvedThisSession, setResolvedThisSession] = useState(false);

  const activeFlow =
    flow &&
    !resolvedThisSession &&
    shouldStartOnboarding({ hasProviders, completionRecord })
      ? flow
      : null;

  if (!activeFlow) return null;

  const handleAccept = () => {
    // Arm checkpoint only on explicit accept — skip must never arm it.
    useOnboardingCheckpointStore.getState().arm();
    setResolvedThisSession(true);
    // Routes may already carry a query string, so pick the right separator.
    const separator = activeFlow.route.includes("?") ? "&" : "?";
    router.push(`${activeFlow.route}${separator}onboarding=${activeFlow.id}`);
  };

  const handleDismiss = () => {
    // Persist dismissal so the gate silently skips on future visits.
    localStorageAdapter.set(
      { id: activeFlow.tour.id, version: activeFlow.tour.version },
      {
        tourId: activeFlow.tour.id,
        version: activeFlow.tour.version,
        state: TOUR_COMPLETION_STATES.DISMISSED,
        completedAt: new Date().toISOString(),
      },
    );
    setResolvedThisSession(true);
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
