"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { CustomCheckboxMutedFindings } from "@/components/filters/custom-checkbox-muted-findings";
import { CustomDatePicker } from "@/components/filters/custom-date-picker";
import { filterFindings } from "@/components/filters/data-filters";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/ui/expandable-section";
import { DataTableFilterCustom } from "@/components/ui/table";
import { useRelatedFilters } from "@/hooks";
import { getCategoryLabel, getGroupLabel } from "@/lib/categories";
import { FilterEntity, FilterType, ScanEntity, ScanProps } from "@/types";
import { ProviderProps } from "@/types/providers";

interface FindingsFiltersProps {
  /** Provider data for ProviderTypeSelector and AccountsSelector */
  providers: ProviderProps[];
  providerIds: string[];
  providerDetails: { [id: string]: FilterEntity }[];
  completedScans: ScanProps[];
  completedScanIds: string[];
  scanDetails: { [key: string]: ScanEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueCategories: string[];
  uniqueGroups: string[];
}

export const FindingsFilters = ({
  providers,
  providerIds,
  providerDetails,
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueCategories,
  uniqueGroups,
}: FindingsFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const { availableScans } = useRelatedFilters({
    providerIds,
    providerDetails,
    completedScanIds,
    scanDetails,
    enableScanRelation: true,
  });

  // Custom filters for the expandable section (removed Provider - now using AccountsSelector)
  const customFilters = [
    ...filterFindings,
    {
      key: FilterType.REGION,
      labelCheckboxGroup: "Regions",
      values: uniqueRegions,
      index: 3,
    },
    {
      key: FilterType.SERVICE,
      labelCheckboxGroup: "Services",
      values: uniqueServices,
      index: 4,
    },
    {
      key: FilterType.RESOURCE_TYPE,
      labelCheckboxGroup: "Resource Type",
      values: uniqueResourceTypes,
      index: 8,
    },
    {
      key: FilterType.CATEGORY,
      labelCheckboxGroup: "Category",
      values: uniqueCategories,
      labelFormatter: getCategoryLabel,
      index: 5,
    },
    {
      key: FilterType.RESOURCE_GROUPS,
      labelCheckboxGroup: "Resource Group",
      values: uniqueGroups,
      labelFormatter: getGroupLabel,
      index: 6,
    },
    {
      key: FilterType.SCAN,
      labelCheckboxGroup: "Scan ID",
      values: availableScans,
      valueLabelMapping: scanDetails,
      index: 7,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;

  return (
    <div className="flex flex-col">
      {/* First row: Provider selectors + Muted checkbox + More Filters button + Clear Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <ProviderTypeSelector providers={providers} />
        </div>
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <AccountsSelector providers={providers} />
        </div>
        <CustomCheckboxMutedFindings />
        {hasCustomFilters && (
          <Button
            variant="outline"
            size="lg"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "Less Filters" : "More Filters"}
            <ChevronDown
              className={`size-4 transition-transform duration-300 ${isExpanded ? "rotate-180" : "rotate-0"}`}
            />
          </Button>
        )}
        <ClearFiltersButton showCount />
      </div>

      {/* Expandable filters section */}
      {hasCustomFilters && (
        <ExpandableSection isExpanded={isExpanded}>
          <DataTableFilterCustom
            filters={customFilters}
            prependElement={<CustomDatePicker />}
            hideClearButton
          />
        </ExpandableSection>
      )}
    </div>
  );
};
