"use client";

import { usePathname, useRouter } from "next/navigation";

import { useAuth } from "@/hooks/use-auth";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  isFirstRunHandled,
  markFirstRunHandled,
  recordFirstRunAttempt,
} from "@/lib/provider-funnel/first-run-marker";
import {
  PROVIDER_FUNNEL_EVENT,
  PROVIDER_FUNNEL_STEP,
  type ProviderFunnelDetail,
  WIZARD_OPEN_SOURCE,
} from "@/lib/provider-funnel/provider-funnel-events";
import { buildAddProviderHref } from "@/lib/providers-navigation";

interface FirstRunRedirectProps {
  // `undefined` = fetch failed/ambiguous; fail-open (never force the first run).
  hasProviders?: boolean;
  // Scopes the first-run marker so one tenant's first run never silences another's.
  tenantId?: string | null;
}

// New-tenant gate. Mounted once in the layout: an empty tenant is sent straight to
// the add-provider wizard, retried per load until the wizard opens once for that
// tenant on this browser (bounded attempts). Renders nothing.
export function FirstRunRedirect({
  hasProviders,
  tenantId = null,
}: FirstRunRedirectProps) {
  const pathname = usePathname();
  const { permissions } = useAuth();
  // Billing must stay usable before a provider exists; leaving it keeps the gate eligible.
  const isBillingRoute =
    pathname === "/billing" || pathname?.startsWith("/billing/");

  // Strict `=== false`: an unknown count fails open. Limited-visibility users list
  // zero providers in a tenant that is not empty, so the permission is required.
  const shouldRedirect =
    hasProviders === false &&
    permissions.manage_providers === true &&
    !isBillingRoute;

  if (!shouldRedirect) return null;

  return <AddProviderRedirect tenantId={tenantId} />;
}

interface AddProviderRedirectProps {
  tenantId: string | null;
}

function AddProviderRedirect({ tenantId }: AddProviderRedirectProps) {
  const router = useRouter();

  useMountEffect(() => {
    if (isFirstRunHandled(tenantId)) return;

    // The wizard opening resolves the first run, whether this redirect got there
    // or the user opened it on their own. Until then each load retries, bounded
    // by the attempt count, so a navigation cut short is not the end of it.
    const resolveOnWizardOpened = (event: Event) => {
      const { detail } = event as CustomEvent<ProviderFunnelDetail>;
      if (detail?.step === PROVIDER_FUNNEL_STEP.WIZARD_OPENED) {
        markFirstRunHandled(tenantId);
      }
    };
    window.addEventListener(PROVIDER_FUNNEL_EVENT, resolveOnWizardOpened);
    recordFirstRunAttempt(tenantId);

    router.replace(buildAddProviderHref(WIZARD_OPEN_SOURCE.FIRST_RUN));

    return () =>
      window.removeEventListener(PROVIDER_FUNNEL_EVENT, resolveOnWizardOpened);
  });

  return null;
}
