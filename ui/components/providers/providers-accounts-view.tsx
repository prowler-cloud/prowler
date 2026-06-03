"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { OnboardingTrigger } from "@/components/onboarding";
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

    // Only clean the one-shot ?addProvider intent from the URL bar, via the
    // History API so it does NOT trigger an RSC refetch. We must not refresh
    // here: the provider-creation actions (addProvider / addCredentialsProvider
    // / checkConnectionProvider) already revalidatePath("/providers"), so the
    // table updates behind the modal. A router.refresh()/replace() on close
    // re-ran the whole /providers Server Component, which read as a full reload.
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
      {/* Renders null; reads the sequence slice + ?onboarding param and force-
          starts the add-provider tour, wiring the tour's wizard-open step to
          this view's imperative open. Suspense satisfies the App Router
          requirement around `useSearchParams`. */}
      <Suspense fallback={null}>
        <OnboardingTrigger
          flow={addProviderFlow}
          stepHandlers={createAddProviderTourStepHandlers(() =>
            openProviderWizard(),
          )}
        />
      </Suspense>
      {hasNoProviders ? (
        <NoProvidersAdded
          action="button"
          containerClassName="min-h-[calc(100dvh-28rem)]"
          onOpenWizard={() => openProviderWizard()}
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
