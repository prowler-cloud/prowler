"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { ApplyFiltersButton } from "@/components/filters/apply-filters-button";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { CustomCheckboxMutedFindings } from "@/components/filters/custom-checkbox-muted-findings";
import { CustomDatePicker } from "@/components/filters/custom-date-picker";
import { filterFindings } from "@/components/filters/data-filters";
import {
  FilterChip,
  FilterSummaryStrip,
} from "@/components/filters/filter-summary-strip";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/ui/expandable-section";
import { DataTableFilterCustom } from "@/components/ui/table";
import { useFilterBatch } from "@/hooks/use-filter-batch";
import { getCategoryLabel, getGroupLabel } from "@/lib/categories";
import { FilterType, ScanEntity } from "@/types";
import { DATA_TABLE_FILTER_MODE } from "@/types/filters";
import { ProviderProps } from "@/types/providers";

import {
  buildFindingsFilterChips,
  getFindingsFilterDisplayValue,
} from "./findings-filters.utils";

interface FindingsFiltersProps {
  /** Provider data for ProviderTypeSelector and AccountsSelector */
  providers: ProviderProps[];
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
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueCategories,
  uniqueGroups,
}: FindingsFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const {
    pendingFilters,
    setPending,
    applyAll,
    discardAll,
    clearAndApply,
    hasChanges,
    changeCount,
    getFilterValue,
  } = useFilterBatch({
    defaultParams: { "filter[muted]": "false" },
  });

  // Custom filters for the expandable section (removed Provider - now using AccountsSelector)
  const customFilters = [
    ...filterFindings.map((filter) => ({
      ...filter,
      labelFormatter: (value: string) =>
        getFindingsFilterDisplayValue(`filter[${filter.key}]`, value, {
          providers,
          scans: scanDetails,
        }),
    })),
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
      values: completedScanIds,
      width: "wide" as const,
      valueLabelMapping: scanDetails,
      labelFormatter: (value: string) =>
        getFindingsFilterDisplayValue(`filter[${FilterType.SCAN}]`, value, {
          providers,
          scans: scanDetails,
        }),
      index: 7,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;

  const filterChips: FilterChip[] = buildFindingsFilterChips(pendingFilters, {
    providers,
    scans: scanDetails,
  });

  // Handler for removing a single chip: update the pending filter to remove that value.
  // setPending handles both "filter[key]" and "key" formats internally.
  const handleChipRemove = (filterKey: string, value: string) => {
    const currentValues = pendingFilters[filterKey] ?? [];
    const nextValues = currentValues.filter((v) => v !== value);
    setPending(filterKey, nextValues);
  };

  // Derive pending muted state for the checkbox.
  // Note: "filter[muted]" participates in batch mode — applyAll includes it
  // when present in pending state, and the defaultParams option ensures
  // filter[muted]=false is applied as a fallback when no muted value is pending.
  const pendingMutedValue = pendingFilters["filter[muted]"];
  const mutedChecked =
    pendingMutedValue !== undefined
      ? pendingMutedValue[0] === "include"
      : undefined;

  // For the date picker, read from pendingFilters
  const pendingDateValues = pendingFilters["filter[inserted_at]"];
  const pendingDateValue =
    pendingDateValues && pendingDateValues.length > 0
      ? pendingDateValues[0]
      : undefined;

  return (
    <div className="flex flex-col">
      {/* First row: Provider selectors + Muted checkbox + More Filters button + Apply/Clear */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <ProviderTypeSelector
            providers={providers}
            onBatchChange={setPending}
            selectedValues={getFilterValue("filter[provider_type__in]")}
          />
        </div>
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <AccountsSelector
            providers={providers}
            onBatchChange={setPending}
            selectedValues={getFilterValue("filter[provider_id__in]")}
            selectedProviderTypes={getFilterValue("filter[provider_type__in]")}
          />
        </div>
        <CustomCheckboxMutedFindings
          onBatchChange={(filterKey, value) => setPending(filterKey, [value])}
          checked={mutedChecked}
        />
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
        <ClearFiltersButton
          showCount
          onClear={clearAndApply}
          pendingCount={
            Object.entries(pendingFilters).filter(([key, values]) => {
              if (!values || values.length === 0) return false;
              // filter[muted]=false is the silent default — don't count it as active
              if (
                key === "filter[muted]" &&
                values.length === 1 &&
                values[0] === "false"
              )
                return false;
              return true;
            }).length
          }
        />
        <ApplyFiltersButton
          hasChanges={hasChanges}
          changeCount={changeCount}
          onApply={applyAll}
          onDiscard={discardAll}
        />
      </div>

      {/* Summary strip: shown below filter bar when there are pending changes */}
      <FilterSummaryStrip chips={filterChips} onRemove={handleChipRemove} />

      {/* Expandable filters section */}
      {hasCustomFilters && (
        <ExpandableSection isExpanded={isExpanded}>
          <DataTableFilterCustom
            filters={customFilters}
            prependElement={
              <CustomDatePicker
                onBatchChange={(filterKey, value) =>
                  setPending(filterKey, value ? [value] : [])
                }
                value={pendingDateValue}
              />
            }
            hideClearButton
            mode={DATA_TABLE_FILTER_MODE.BATCH}
            onBatchChange={setPending}
            getFilterValue={getFilterValue}
          />
        </ExpandableSection>
      )}
    </div>
  );
};
