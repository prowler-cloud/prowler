"use client";

import { useState } from "react";

import { ProviderWizardModal } from "@/components/providers/wizard";
import { LaunchScanWorkflow } from "@/components/scans/launch-workflow";
import { NoProvidersAdded } from "@/components/scans/no-providers-added";
import { NoProvidersConnected } from "@/components/scans/no-providers-connected";
import { CustomBanner } from "@/components/ui/custom/custom-banner";

export interface ScanProviderInfo {
  providerId: string;
  alias: string;
  providerType: string;
  uid: string;
  connected: boolean;
}

interface ScansLaunchSectionProps {
  providers: ScanProviderInfo[];
  hasManageScansPermission?: boolean;
  thereIsNoProviders: boolean;
  thereIsNoProvidersConnected?: boolean;
}

export function ScansLaunchSection({
  providers,
  hasManageScansPermission,
  thereIsNoProviders,
  thereIsNoProvidersConnected,
}: ScansLaunchSectionProps) {
  const [isProviderWizardOpen, setIsProviderWizardOpen] = useState(false);

  return (
    <>
      {thereIsNoProviders ? (
        <NoProvidersAdded onOpenWizard={() => setIsProviderWizardOpen(true)} />
      ) : !hasManageScansPermission ? (
        <CustomBanner
          title={"Access Denied"}
          message={"You don't have permission to launch the scan."}
        />
      ) : thereIsNoProvidersConnected ? (
        <NoProvidersConnected />
      ) : (
        <LaunchScanWorkflow providers={providers} />
      )}
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={setIsProviderWizardOpen}
      />
    </>
  );
}
