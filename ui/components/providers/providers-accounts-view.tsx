"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState, useTransition } from "react";

import { AddProviderButton } from "@/components/providers/add-provider-button";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import { NoProvidersAdded } from "@/components/providers/no-providers-added";
import { ProvidersAccountsTable } from "@/components/providers/providers-accounts-table";
import { ProvidersFilters } from "@/components/providers/providers-filters";
import { SkeletonTableProviders } from "@/components/providers/table";
import { ProviderWizardModal } from "@/components/providers/wizard";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
import {
  ADD_PROVIDER_SEARCH_PARAM,
  ADD_PROVIDER_SEARCH_VALUE,
} from "@/lib/providers-navigation";
import type { FilterOption, MetaDataProps, ProviderProps } from "@/types";
import type { ProvidersTableRow } from "@/types/providers-table";

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
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [isRefreshing, startRefreshTransition] = useTransition();
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

    if (!open) {
      setProviderWizardInitialData(undefined);
      setOrgWizardInitialData(undefined);

      if (searchParams.has(ADD_PROVIDER_SEARCH_PARAM)) {
        const params = new URLSearchParams(searchParams.toString());
        params.delete(ADD_PROVIDER_SEARCH_PARAM);
        const query = params.toString();
        // Clean the URL bar without a Next.js navigation. router.replace would
        // re-run the /providers Server Component (RSC refetch + flicker) right
        // as the modal closes; replaceState only mutates the address bar and
        // Next keeps useSearchParams in sync with it.
        window.history.replaceState(
          null,
          "",
          query ? `${pathname}?${query}` : pathname,
        );
      }

      // We own the post-close refresh (the wizard skips it via refreshOnClose)
      // so we can wrap it in a transition: isRefreshing lets us show the table
      // skeleton instead of flashing the empty state while we re-check for the
      // freshly added provider.
      startRefreshTransition(() => {
        router.refresh();
      });
    }
  };

  return (
    <>
      {hasNoProviders ? (
        isRefreshing ? (
          <SkeletonTableProviders />
        ) : (
          <NoProvidersAdded
            action="button"
            containerClassName="min-h-[calc(100dvh-28rem)]"
            onOpenWizard={() => openProviderWizard()}
          />
        )
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
