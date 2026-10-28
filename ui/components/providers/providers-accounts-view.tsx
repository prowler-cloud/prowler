"use client";

import { Info } from "lucide-react";
import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

import { AddProviderButton } from "@/components/providers/add-provider-button";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import { NoProvidersAdded } from "@/components/providers/no-providers-added";
import { ProvidersAccountsTable } from "@/components/providers/providers-accounts-table";
import { ProvidersFilters } from "@/components/providers/providers-filters";
import { RegistryLogosContext } from "@/components/providers/table/registry-row-logo";
import { ProviderWizardModal } from "@/components/providers/wizard";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  dispatchProviderFunnel,
  PROVIDER_FUNNEL_STEP,
  WIZARD_OPEN_SOURCE,
  type WizardOpenSource,
} from "@/lib/provider-funnel/provider-funnel-events";
import {
  ADD_PROVIDER_SEARCH_PARAM,
  ADD_PROVIDER_SEARCH_VALUE,
  ADD_PROVIDER_SOURCE_PARAM,
  resolveAddProviderSource,
} from "@/lib/providers-navigation";
import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProviderGroup } from "@/types/components";
import {
  HIERARCHY_STATUS,
  type HierarchyStatus,
  type ProvidersTableRow,
} from "@/types/providers-table";
import type {
  ScanConfigurationData,
  ScanConfigurationListStatus,
} from "@/types/scan-configurations";
import type { ScanScheduleCapability } from "@/types/schedules";

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
  hierarchyStatus?: HierarchyStatus;
  /** Registry logo per provider type; rows render before it resolves. */
  registryLogos?: Promise<Record<string, string>>;
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
  hierarchyStatus = HIERARCHY_STATUS.AVAILABLE,
  registryLogos,
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

  const signalWizardOpened = (source: WizardOpenSource) =>
    dispatchProviderFunnel({
      step: PROVIDER_FUNNEL_STEP.WIZARD_OPENED,
      source,
    });

  // A URL-opened wizard never goes through openProviderWizard, so signal it on mount.
  useMountEffect(() => {
    if (!shouldOpenProviderWizardFromUrl) return;
    signalWizardOpened(
      resolveAddProviderSource(searchParams.get(ADD_PROVIDER_SOURCE_PARAM)),
    );
  });

  const openProviderWizard = (
    source: WizardOpenSource,
    initialData?: ProviderWizardInitialData,
  ) => {
    signalWizardOpened(source);
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
      params.delete(ADD_PROVIDER_SOURCE_PARAM);
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
      {hasNoProviders ? (
        <NoProvidersAdded
          action="button"
          containerClassName="min-h-[calc(100dvh-28rem)]"
          onOpenWizard={() =>
            openProviderWizard(WIZARD_OPEN_SOURCE.EMPTY_STATE)
          }
        />
      ) : (
        <div className="flex flex-col gap-6">
          {hierarchyStatus === HIERARCHY_STATUS.UNAVAILABLE && (
            <Alert>
              <Info />
              <AlertDescription>
                Organization grouping is incomplete. Some providers may appear
                ungrouped.
              </AlertDescription>
            </Alert>
          )}
          <ProvidersFilters
            filters={filters}
            providers={providers}
            providerGroups={providerGroups}
            actions={
              <>
                <MutedFindingsConfigButton />
                <AddProviderButton
                  onOpenWizard={() =>
                    openProviderWizard(WIZARD_OPEN_SOURCE.PAGE_BUTTON)
                  }
                />
              </>
            }
          />
          <RegistryLogosContext value={registryLogos ?? null}>
            <ProvidersAccountsTable
              isCloud={isCloud}
              metadata={metadata}
              rows={rows}
              scanScheduleCapability={scanScheduleCapability}
              scanConfigs={scanConfigs}
              scanConfigStatus={scanConfigStatus}
              onOpenProviderWizard={(initialData) =>
                openProviderWizard(WIZARD_OPEN_SOURCE.ROW_ACTION, initialData)
              }
              onOpenOrganizationWizard={openOrganizationWizard}
            />
          </RegistryLogosContext>
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
