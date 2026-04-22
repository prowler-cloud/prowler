"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
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

import { ScanSelector, SelectScanComplianceDataProps } from "./scan-selector";

interface ComplianceFiltersProps {
  scans: SelectScanComplianceDataProps["scans"];
  uniqueRegions: string[];
  selectedScanId: string;
}

export const ComplianceFilters = ({
  scans,
  uniqueRegions,
  selectedScanId,
}: ComplianceFiltersProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();

  const handleScanChange = (selectedKey: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("scanId", selectedKey);
    router.push(`?${params.toString()}`, { scroll: false });
  };

  const regionValues =
    searchParams.get("filter[region__in]")?.split(",").filter(Boolean) ?? [];

  return (
    <div className="flex max-w-4xl flex-wrap items-center gap-4">
      <div className="w-full sm:max-w-[380px] sm:min-w-[200px] sm:flex-1">
        <ScanSelector
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectionChange={handleScanChange}
        />
      </div>
      {uniqueRegions.length > 0 && (
        <div className="w-full sm:max-w-[280px] sm:min-w-[200px] sm:flex-1">
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
