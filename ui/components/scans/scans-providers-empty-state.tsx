"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";
import { LAUNCH_SCAN_SEARCH_PARAM } from "@/lib/scans-navigation";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

import { NoProvidersAdded } from "./no-providers-added";
import { NoProvidersConnected } from "./no-providers-connected";

interface ScansProvidersEmptyStateProps {
  thereIsNoProviders: boolean;
}

export function ScansProvidersEmptyState({
  thereIsNoProviders,
}: ScansProvidersEmptyStateProps) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isProviderWizardOpen, setIsProviderWizardOpen] = useState(false);
  // Mirrors the wizard open state into the shared store so the layout-level
  // onboarding checkpoint watcher can defer its dialog while the wizard is open.
  const setWizardOpenSignal = useProviderWizardStore(
    (state) => state.setIsOpen,
  );

  const openProviderWizard = () => {
    if (searchParams.has(LAUNCH_SCAN_SEARCH_PARAM)) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete(LAUNCH_SCAN_SEARCH_PARAM);
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, {
        scroll: false,
      });
    }

    setIsProviderWizardOpen(true);
    setWizardOpenSignal(true);
  };

  const handleWizardOpenChange = (open: boolean) => {
    setIsProviderWizardOpen(open);
    setWizardOpenSignal(open);
  };

  return (
    <>
      {thereIsNoProviders ? (
        <NoProvidersAdded onOpenWizard={openProviderWizard} />
      ) : (
        <NoProvidersConnected />
      )}
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={handleWizardOpenChange}
      />
    </>
  );
}
