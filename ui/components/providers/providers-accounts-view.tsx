"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { OnboardingTrigger, PageReady } from "@/components/onboarding";
import { AddProviderButton } from "@/components/providers/add-provider-button";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import { NoProvidersAdded } from "@/components/providers/no-providers-added";
import { ProvidersAccountsTable } from "@/components/providers/providers-accounts-table";
import { ProvidersFilters } from "@/components/providers/providers-filters";
import { ProviderWizardModal } from "@/components/providers/wizard";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { getFlowById } from "@/lib/onboarding";
import {
  ADD_PROVIDER_SEARCH_PARAM,
  ADD_PROVIDER_SEARCH_VALUE,
} from "@/lib/providers-navigation";
import { createAddProviderTourStepHandlers } from "@/lib/tours/add-provider.tour";
import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProvidersTableRow } from "@/types/providers-table";

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
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const hasNoProviders = providers.length === 0;
  const shouldOpenProviderWizardFromUrl =
    searchParams.get(ADD_PROVIDER_SEARCH_PARAM) === ADD_PROVIDER_SEARCH_VALUE;
  const [isProviderWizardOpen, setIsProviderWizardOpen] = useState(
    () => shouldOpenProviderWizardFromUrl,
  );
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

    if (open) return;

    setProviderWizardInitialData(undefined);
    setOrgWizardInitialData(undefined);

    // Remove ?addProvider via History API (not router.replace) to avoid an RSC refetch;
    // revalidatePath in the creation actions already refreshes the table.
    if (searchParams.has(ADD_PROVIDER_SEARCH_PARAM)) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete(ADD_PROVIDER_SEARCH_PARAM);
      const query = params.toString();
      window.history.replaceState(
        null,
        "",
        query ? `${pathname}?${query}` : pathname,
      );
    }
  };

  return (
    <>
      {/* Suspense required: OnboardingTrigger reads useSearchParams */}
      <Suspense fallback={null}>
        <OnboardingTrigger
          flow={addProviderFlow}
          stepHandlers={createAddProviderTourStepHandlers(() =>
            openProviderWizard(),
          )}
        />
      </Suspense>
      {/* Signals the navbar that this route's data has loaded (enables the replay icon). */}
      <PageReady />
      {hasNoProviders ? (
        <NoProvidersAdded
          action="button"
          containerClassName="min-h-[calc(100dvh-28rem)]"
          onOpenWizard={() => openProviderWizard()}
          ctaTourId="add-provider-trigger"
        />
      ) : (
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
      )}
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={handleWizardOpenChange}
        initialData={providerWizardInitialData}
        orgInitialData={orgWizardInitialData}
        refreshOnClose={false}
      />
    </>
  );
}
