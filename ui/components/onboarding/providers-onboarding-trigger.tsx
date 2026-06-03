"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { getFlowById, type OnboardingFlow } from "@/lib/onboarding";
import { createAddProviderTourStepHandlers } from "@/lib/tours/add-provider.tour";
import { useDriverTour } from "@/lib/tours/use-driver-tour";

interface ProvidersOnboardingTriggerProps {
  // Imperative wizard open owned by the providers view; the tour's `trigger`
  // step calls this to launch the Add Provider wizard.
  openWizard: () => void;
}

const ONBOARDING_PARAM = "onboarding";

// Reads `?onboarding=<flowId>` and, when it matches a known flow, force-starts
// that flow's tour over the real page surface, then strips the param so a
// refresh does not re-trigger. Renders nothing.
export function ProvidersOnboardingTrigger({
  openWizard,
}: ProvidersOnboardingTriggerProps) {
  const searchParams = useSearchParams();
  // `useSearchParams` can return null outside a router/Suspense context.
  const flowId = searchParams?.get(ONBOARDING_PARAM) ?? null;
  const flow = flowId ? getFlowById(flowId) : undefined;

  if (!flow) return null;

  // Delegated to an inner component so the `useDriverTour` hook is always
  // called unconditionally for the resolved flow (Rules of Hooks): this whole
  // tree only mounts when a valid flow is present.
  return <OnboardingTourRunner flow={flow} openWizard={openWizard} />;
}

interface OnboardingTourRunnerProps {
  flow: OnboardingFlow;
  openWizard: () => void;
}

function OnboardingTourRunner({ flow, openWizard }: OnboardingTourRunnerProps) {
  const router = useRouter();
  const pathname = usePathname();
  const hasStartedRef = useRef(false);

  const { start } = useDriverTour(flow.tour, {
    autoOpen: false,
    stepHandlers: createAddProviderTourStepHandlers(openWizard),
  });

  useEffect(() => {
    // Force-start once: bypasses the `hasCompleted` short-circuit so the
    // re-trigger works even with an existing completion record.
    if (hasStartedRef.current) return;
    hasStartedRef.current = true;

    start();
    // Strip the param so a hard reload does not re-launch the tour.
    router.replace(pathname);
  }, [start, router, pathname]);

  return null;
}
