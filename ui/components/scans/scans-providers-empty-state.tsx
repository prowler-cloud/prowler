"use client";

import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";

import { NoProvidersAdded } from "./no-providers-added";
import { NoProvidersConnected } from "./no-providers-connected";

interface ScansProvidersEmptyStateProps {
  thereIsNoProviders: boolean;
}

export function ScansProvidersEmptyState({
  thereIsNoProviders,
}: ScansProvidersEmptyStateProps) {
  const [isProviderWizardOpen, setIsProviderWizardOpen] = useState(false);

  return (
    <>
      {thereIsNoProviders ? (
        <NoProvidersAdded onOpenWizard={() => setIsProviderWizardOpen(true)} />
      ) : (
        <NoProvidersConnected />
      )}
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={setIsProviderWizardOpen}
      />
    </>
  );
}
