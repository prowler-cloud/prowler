"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { ProviderGroupSelector } from "@/app/(prowler)/_overview/_components/provider-group-selector";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { COMPLIANCE_PROVIDER_FILTER_KEYS } from "@/lib/compliance/compliance-provider-filters";
import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import { ScanSelector, SelectScanComplianceDataProps } from "./scan-selector";

// Clearing scanId/page is the inverse of the provider selectors'
// paramsToDeleteOnChange — together they enforce the backend scan_id ⊕ provider XOR.
const PROVIDER_PARAMS_TO_DELETE = ["scanId", "page"];
const SELECTOR_WIDTH = "w-full sm:max-w-[280px] sm:min-w-[200px] sm:flex-1";

interface ComplianceFiltersProps {
  scans: SelectScanComplianceDataProps["scans"];
  uniqueRegions: string[];
  /** Null in aggregated mode (provider filters drive the scope, no single scan). */
  selectedScanId: string | null;
  providers: ProviderProps[];
  providerGroups: ProviderGroup[];
}

export const ComplianceFilters = ({
  scans,
  uniqueRegions,
  selectedScanId,
  providers,
  providerGroups,
}: ComplianceFiltersProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();

  // XOR: choosing a single scan clears any active provider-scope filters.
  const handleScanChange = (selectedKey: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("scanId", selectedKey);
    COMPLIANCE_PROVIDER_FILTER_KEYS.forEach((key) => params.delete(key));
    params.delete("page");
    router.push(`?${params.toString()}`, { scroll: false });
  };

  const regionValues =
    searchParams.get("filter[region__in]")?.split(",").filter(Boolean) ?? [];

  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="w-full sm:max-w-[380px] sm:min-w-[200px] sm:flex-1">
        <ScanSelector
          scans={scans}
          selectedScanId={selectedScanId ?? ""}
          onSelectionChange={handleScanChange}
        />
      </div>
      {/* Provider-scope filters: selecting any switches to aggregated mode and clears scanId. */}
      <ProviderAccountSelectors
        providers={providers}
        accountFilterKey="provider_id__in"
        accountValue="id"
        paramsToDeleteOnChange={PROVIDER_PARAMS_TO_DELETE}
        providerSelectorClassName={SELECTOR_WIDTH}
        accountSelectorClassName={SELECTOR_WIDTH}
      />
      <div className={SELECTOR_WIDTH}>
        <ProviderGroupSelector
          groups={providerGroups}
          paramsToDeleteOnChange={PROVIDER_PARAMS_TO_DELETE}
        />
      </div>
      {uniqueRegions.length > 0 && (
        <div className={SELECTOR_WIDTH}>
          <MultiSelect
            values={regionValues}
            onValuesChange={(values) => updateFilter("region__in", values)}
          >
            <MultiSelectTrigger size="default">
              <MultiSelectValue placeholder="All Regions" />
            </MultiSelectTrigger>
            <MultiSelectContent search={false} width="wide">
              <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
              <MultiSelectSeparator />
              {uniqueRegions.map((region) => (
                <MultiSelectItem key={region} value={region}>
                  {region}
                </MultiSelectItem>
              ))}
            </MultiSelectContent>
          </MultiSelect>
        </div>
      )}
      <ClearFiltersButton showCount />
    </div>
  );
};
