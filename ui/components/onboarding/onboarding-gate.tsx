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
  // Tri-state: `true`/`false` from a successful provider fetch, `undefined`
  // when the layout could not determine provider state (failed/ambiguous
  // fetch). `undefined` must fail open — never force the modal on an unknown
  // state.
  hasProviders?: boolean;
}

// Mandatory new-user gate. Mounted once in the (prowler) layout. The decision is
// DERIVED during render from the `hasProviders` signal plus the gate flow's
// completion record (read SSR-safely via `useTourCompletion`/useSyncExternalStore,
// so the server renders nothing and there is no hydration mismatch — no effect).
export function OnboardingGate({ hasProviders }: OnboardingGateProps) {
  const router = useRouter();

  // The mandatory gate ONLY ever forces the FIRST ordered flow (the new-user
  // entry point, `add-provider`). The remaining sequence flows are reached via
  // the post-connect checkpoint and the avatar replay list — never the gate.
  const flow = getOrderedFlows()[0] ?? null;

  // `useTourCompletion` returns `null` on the server and first client render, so
  // the gate stays closed until the record resolves client-side without an
  // effect or a hydration mismatch.
  const completionRecord = useTourCompletion(flow?.tour ?? null);

  // Session-local resolution: once the user accepts or dismisses, the gate
  // closes for this mount via the handler below — no effect re-deriving state.
  const [resolvedThisSession, setResolvedThisSession] = useState(false);

  // `shouldStartOnboarding` receives the RAW (possibly `undefined`)
  // `hasProviders` and applies the strict `=== false` fail-open guard, so an
  // ambiguous provider state never forces the modal. A completion/dismissal
  // record keeps the gate silent.
  const activeFlow =
    flow &&
    !resolvedThisSession &&
    shouldStartOnboarding({ hasProviders, completionRecord })
      ? flow
      : null;

  if (!activeFlow) return null;

  const handleAccept = () => {
    // Arm the post-connect checkpoint: only a user who explicitly started
    // onboarding here may later see the "keep exploring?" dialog. Skipping the
    // modal must never arm it, so this lives in accept only.
    useOnboardingCheckpointStore.getState().arm();

    // Hand off via the URL; the providers page's trigger starts the tour. No
    // record is written here — completion is persisted only when the tour
    // finishes or is skipped.
    setResolvedThisSession(true);
    router.push(`${activeFlow.route}?onboarding=${activeFlow.id}`);
  };

  const handleDismiss = () => {
    // Persist a dismissal so the gate stops re-prompting in this browser, and
    // resolve the session so the modal closes immediately.
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
