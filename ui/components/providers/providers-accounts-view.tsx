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
import {
  ADD_PROVIDER_TOUR_TARGETS,
  addProviderTour,
} from "@/lib/tours/add-provider.tour";
import {
  advanceActiveTourWhenReady,
  getTourTargetSelector,
} from "@/lib/tours/use-driver-tour";
import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProviderGroup } from "@/types/components";
import type { ProvidersTableRow } from "@/types/providers-table";
import type {
  ScanConfigurationData,
  ScanConfigurationListStatus,
} from "@/types/scan-configurations";
import type { ScanScheduleCapability } from "@/types/schedules";

const addProviderFlow = getFlowById("add-provider")!;

// Softer overlay for this onboarding tour — a heavy dim over the wizard feels harsh
// while the user fills the form. Module-level constant keeps the driver config stable
// across renders (useDriverTour recreates the driver when configOverrides identity
// changes).
const ADD_PROVIDER_TOUR_CONFIG = { overlayOpacity: 0.45 } as const;

// The tour's "trigger" step auto-advances when the wizard opens; this is the anchor
// it waits for (the provider-type selector inside the wizard).
const PROVIDER_TYPE_TOUR_SELECTOR = getTourTargetSelector(
  addProviderTour.id,
  ADD_PROVIDER_TOUR_TARGETS.PROVIDER_TYPE,
);

interface ProvidersAccountsViewProps {
  isCloud: boolean;
  filters: FilterOption[];
  metadata?: MetaDataProps;
  providers: ProviderProps[];
  providerGroups?: ProviderGroup[];
  rows: ProvidersTableRow[];
  /** Cloud overlay seam for provider-creation scan launch. */
  scanScheduleCapability?: ScanScheduleCapability;
  /** All scan configurations in the tenant, for the provider row's associate/
   * disassociate action (Cloud-only). */
  scanConfigs?: ScanConfigurationData[];
  scanConfigStatus?: ScanConfigurationListStatus;
  isScanLimitReached?: boolean;
}

export function ProvidersAccountsView({
  isCloud,
  filters,
  metadata,
  providers,
  providerGroups = [],
  rows,
  scanScheduleCapability,
  scanConfigs,
  scanConfigStatus,
  isScanLimitReached,
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
    // If the add-provider tour is on its "trigger" step, opening the wizard is the
    // advance signal: move to the provider-type step once it mounts. No-op otherwise.
    advanceActiveTourWhenReady(PROVIDER_TYPE_TOUR_SELECTOR);
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
          configOverrides={ADD_PROVIDER_TOUR_CONFIG}
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
            providerGroups={providerGroups}
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
            scanScheduleCapability={scanScheduleCapability}
            scanConfigs={scanConfigs}
            scanConfigStatus={scanConfigStatus}
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
        scanScheduleCapability={scanScheduleCapability}
        isScanLimitReached={isScanLimitReached}
      />
    </>
  );
}
