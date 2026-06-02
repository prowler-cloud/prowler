"use client";

import { Suspense, useState } from "react";

import { OnboardingTrigger } from "@/components/onboarding";
import { AddProviderButton } from "@/components/providers/add-provider-button";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import { ProvidersAccountsTable } from "@/components/providers/providers-accounts-table";
import { ProvidersFilters } from "@/components/providers/providers-filters";
import { ProviderWizardModal } from "@/components/providers/wizard";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { getFlowById } from "@/lib/onboarding";
import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProvidersTableRow } from "@/types/providers-table";

// Resolved once: the registry is static, so the add-provider flow that this
// route owns never changes at runtime.
const addProviderFlow = getFlowById("add-provider")!;

interface ProvidersAccountsViewProps {
  isCloud: boolean;
  filters: FilterOption[];
  metadata?: MetaDataProps;
  providers: ProviderProps[];
  rows: ProvidersTableRow[];
}

export function ProvidersAccountsView({
  isCloud,
  filters,
  metadata,
  providers,
  rows,
}: ProvidersAccountsViewProps) {
  const [isProviderWizardOpen, setIsProviderWizardOpen] = useState(false);
  const [providerWizardInitialData, setProviderWizardInitialData] = useState<
    ProviderWizardInitialData | undefined
  >(undefined);
  const [orgWizardInitialData, setOrgWizardInitialData] = useState<
    OrgWizardInitialData | undefined
  >(undefined);

  const openProviderWizard = (initialData?: ProviderWizardInitialData) => {
    setOrgWizardInitialData(undefined);
    setProviderWizardInitialData(initialData);
    setIsProviderWizardOpen(true);
  };

  const openOrganizationWizard = (initialData: OrgWizardInitialData) => {
    setProviderWizardInitialData(undefined);
    setOrgWizardInitialData(initialData);
    setIsProviderWizardOpen(true);
  };

  const handleWizardOpenChange = (open: boolean) => {
    setIsProviderWizardOpen(open);

    if (!open) {
      setProviderWizardInitialData(undefined);
      setOrgWizardInitialData(undefined);
    }
  };

  return (
    <>
      {/* Renders null; reads the sequence slice + ?onboarding param and force-
          starts the add-provider tour. The tour ends at the Add Provider
          button (no step handlers, no wizard-open from the tour), so the driver
          overlay never sits on top of the wizard's Radix dialog. Suspense
          satisfies the App Router requirement around `useSearchParams`. */}
      <Suspense fallback={null}>
        <OnboardingTrigger flow={addProviderFlow} />
      </Suspense>
      <div className="flex flex-col gap-6">
        <ProvidersFilters
          filters={filters}
          providers={providers}
          actions={
            <>
              <MutedFindingsConfigButton />
              <AddProviderButton onOpenWizard={() => openProviderWizard()} />
            </>
          }
        />
        <ProvidersAccountsTable
          isCloud={isCloud}
          metadata={metadata}
          rows={rows}
          onOpenProviderWizard={openProviderWizard}
          onOpenOrganizationWizard={openOrganizationWizard}
        />
      </div>
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={handleWizardOpenChange}
        initialData={providerWizardInitialData}
        orgInitialData={orgWizardInitialData}
      />
    </>
  );
}
