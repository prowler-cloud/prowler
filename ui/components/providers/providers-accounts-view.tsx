"use client";

import { useState } from "react";

import { AddProviderButton } from "@/components/providers/add-provider-button";
import { MutedFindingsConfigButton } from "@/components/providers/muted-findings-config-button";
import { ProvidersAccountsTable } from "@/components/providers/providers-accounts-table";
import { ProvidersFilters } from "@/components/providers/providers-filters";
import { ProviderWizardModal } from "@/components/providers/wizard";
import type {
  OrgWizardInitialData,
  ProviderWizardInitialData,
} from "@/components/providers/wizard/types";
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
      <ProviderWizardModal
        open={isProviderWizardOpen}
        onOpenChange={handleWizardOpenChange}
        initialData={providerWizardInitialData}
        orgInitialData={orgWizardInitialData}
      />
    </>
  );
}
