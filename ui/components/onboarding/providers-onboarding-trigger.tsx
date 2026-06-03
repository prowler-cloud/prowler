"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { getFlowById, type OnboardingFlow } from "@/lib/onboarding";
import { createAddProviderTourStepHandlers } from "@/lib/tours/add-provider.tour";
import { useDriverTour } from "@/lib/tours/use-driver-tour";

interface ProvidersOnboardingTriggerProps {
  // Imperative wizard open owned by the providers view; the tour's `trigger`
  // step calls this to launch the Add Provider wizard.
  openWizard: () => void;
}

const ONBOARDING_PARAM = "onboarding";

// A single, latched trigger request. `key` lets us mount a FRESH runner per
// re-trigger so the tour can be restarted repeatedly.
interface OnboardingRequest {
  flow: OnboardingFlow;
  key: number;
}

// Reads `?onboarding=<flowId>` and, when it matches a known flow, force-starts
// that flow's tour over the real page surface, then strips the param so a
// refresh does not re-trigger. Renders nothing.
export function ProvidersOnboardingTrigger({
  openWizard,
}: ProvidersOnboardingTriggerProps) {
  const searchParams = useSearchParams();
  // `useSearchParams` can return null outside a router/Suspense context.
  const flowId = searchParams?.get(ONBOARDING_PARAM) ?? null;

  // The flow is LATCHED into state rather than derived from the live params on
  // every render. Once latched, stripping the param does NOT unmount the
  // runner — which previously destroyed the just-started tour.
  const [request, setRequest] = useState<OnboardingRequest | null>(null);
  const keyRef = useRef(0);

  useEffect(() => {
    if (!flowId) return;
    const flow = getFlowById(flowId);
    if (!flow) return;

    keyRef.current += 1;
    setRequest({ flow, key: keyRef.current });

    // Strip the param via history so a hard reload does not re-launch the tour.
    // We use `window.history.replaceState` instead of `router.replace` so that
    // clearing the param does NOT re-trigger `useSearchParams` reactivity or a
    // server route round-trip. The latched runner therefore stays mounted.
    window.history.replaceState(null, "", window.location.pathname);
  }, [flowId]);

  if (!request) return null;

  // Keyed so each re-trigger mounts a FRESH runner (fresh `hasStartedRef`),
  // preserving "restart works repeatedly". The runner calls `useDriverTour`
  // unconditionally, so Rules of Hooks hold even though this parent can return
  // null above.
  return (
    <OnboardingTourRunner
      key={request.key}
      flow={request.flow}
      openWizard={openWizard}
    />
  );
}

interface OnboardingTourRunnerProps {
  flow: OnboardingFlow;
  openWizard: () => void;
}

function OnboardingTourRunner({ flow, openWizard }: OnboardingTourRunnerProps) {
  const { start } = useDriverTour(flow.tour, {
    autoOpen: false,
    stepHandlers: createAddProviderTourStepHandlers(openWizard),
  });

  // Force-start once per mount. This bypasses the `hasCompleted` short-circuit
  // so re-trigger works even with an existing completion record.
  //
  // The empty dependency array is intentional (NOT `[start]`): `start` gets a
  // new identity every render and always reads the latest `driverRef.current`,
  // so a single call on mount is correct. A `hasStartedRef` guard must NOT be
  // used here: under React StrictMode (dev) the effect runs setup → cleanup →
  // setup; the first setup starts the tour, the cleanup destroys it, and a ref
  // guard would then skip the re-start on the second setup, leaving no visible
  // tour. Mounting a fresh runner per re-trigger (via the parent `key`) already
  // guarantees one start per intentional trigger.
  useEffect(() => {
    start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return null;
}
