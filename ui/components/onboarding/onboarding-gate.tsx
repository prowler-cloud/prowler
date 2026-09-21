"use client";

import { usePathname, useRouter } from "next/navigation";

import { useAuth } from "@/hooks/use-auth";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  getOrderedFlows,
  type OnboardingFlow,
  shouldStartOnboarding,
} from "@/lib/onboarding";
import {
  isFirstRunHandled,
  markFirstRunHandled,
} from "@/lib/onboarding/first-run-marker";
import { WIZARD_OPEN_SOURCE } from "@/lib/provider-funnel/provider-funnel-events";
import { buildAddProviderHref } from "@/lib/providers-navigation";
import { isCloud } from "@/lib/shared/env";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";
import { useTourCompletion } from "@/lib/tours/use-tour-completion";
import { useOnboardingCheckpointStore } from "@/store/onboarding-checkpoint";

interface OnboardingGateProps {
  // `undefined` = fetch failed/ambiguous; fail-open (never force the first run).
  hasProviders?: boolean;
}

// New-tenant gate. Mounted once in the layout: an empty tenant is sent straight to
// the add-provider wizard, once per browser. Renders nothing.
export function OnboardingGate({ hasProviders }: OnboardingGateProps) {
  const pathname = usePathname();
  const { permissions } = useAuth();
  // Billing must stay usable before onboarding; leaving it keeps the gate eligible.
  const isBillingRoute =
    pathname === "/billing" || pathname?.startsWith("/billing/");

  // Gate forces only the first flow (`add-provider`); remaining flows come via checkpoint/replay.
  const flow = getOrderedFlows()[0] ?? null;

  // Returns null on server/first render; the redirect re-reads storage before acting.
  const completionRecord = useTourCompletion(flow?.tour ?? null);

  const shouldRedirect =
    flow !== null &&
    !isBillingRoute &&
    shouldStartOnboarding({
      hasProviders,
      canManageProviders: permissions.manage_providers === true,
      completionRecord,
    });

  if (!shouldRedirect) return null;

  return <FirstRunRedirect flow={flow} />;
}

interface FirstRunRedirectProps {
  flow: OnboardingFlow;
}

function FirstRunRedirect({ flow }: FirstRunRedirectProps) {
  const router = useRouter();

  useMountEffect(() => {
    // Hydration renders with an empty completion snapshot, so decide from storage here.
    const tourId = { id: flow.tour.id, version: flow.tour.version };
    if (isFirstRunHandled() || localStorageAdapter.get(tourId) !== null) return;

    markFirstRunHandled();

    const addProviderHref = buildAddProviderHref(WIZARD_OPEN_SOURCE.FIRST_RUN);
    if (!isCloud()) {
      router.replace(addProviderHref);
      return;
    }

    // Tours and the post-connect checkpoint are Cloud-only.
    useOnboardingCheckpointStore.getState().arm();
    router.replace(`${addProviderHref}&onboarding=${flow.id}`);
  });

  return null;
}
