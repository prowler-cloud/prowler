"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { ApplyFiltersButton } from "@/components/filters/apply-filters-button";
import { BatchFiltersLayout } from "@/components/filters/batch-filters-layout";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import {
  FilterChip,
  FilterSummaryStrip,
} from "@/components/filters/filter-summary-strip";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/ui/expandable-section";
import { DataTableFilterCustom } from "@/components/ui/table";
import { useFilterBatch } from "@/hooks/use-filter-batch";
import { getGroupLabel } from "@/lib/categories";
import { DATA_TABLE_FILTER_MODE } from "@/types/filters";
import { ProviderProps } from "@/types/providers";

import {
  buildResourcesFilterChips,
  getResourcesFilterDisplayValue,
} from "./resources-filters.utils";

interface ResourcesFiltersProps {
  providers: ProviderProps[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueGroups: string[];
}

const countVisibleFilterKeys = (filters: Record<string, string[]>): number =>
  Object.values(filters).filter((values) => values.length > 0).length;

export const ResourcesFilters = ({
  providers,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueGroups,
}: ResourcesFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const {
    appliedFilters,
    pendingFilters,
    changedFilters,
    setPending,
    applyAll,
    discardAll,
    clearAndApply,
    removeAppliedAndApply,
    hasChanges,
    changeCount,
    getFilterValue,
  } = useFilterBatch();

  // Custom filters for the expandable section
  const customFilters = [
    {
      key: "region__in",
      labelCheckboxGroup: "Regions",
      values: uniqueRegions,
      index: 1,
    },
    {
      key: "service__in",
      labelCheckboxGroup: "Services",
      values: uniqueServices,
      index: 2,
    },
    {
      key: "type__in",
      labelCheckboxGroup: "Types",
      values: uniqueResourceTypes,
      index: 3,
    },
    {
      key: "groups__in",
      labelCheckboxGroup: "Groups",
      values: uniqueGroups,
      labelFormatter: getGroupLabel,
      index: 4,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;
  const appliedFilterChips: FilterChip[] = buildResourcesFilterChips(
    appliedFilters,
    providers,
  );
  const pendingFilterChips: FilterChip[] = buildResourcesFilterChips(
    changedFilters,
    providers,
  );
  const appliedCount = countVisibleFilterKeys(appliedFilters);
  const showAppliedRow = appliedFilterChips.length > 0;
  const showPendingRow = hasChanges;

  const handleChipRemove = (filterKey: string, value?: string) => {
    if (value === undefined) {
      setPending(filterKey, []);
      return;
    }

    const currentValues = pendingFilters[filterKey] ?? [];
    const nextValues = currentValues.filter((item) => item !== value);
    setPending(filterKey, nextValues);
  };

  const expandedFilters = hasCustomFilters ? (
    <ExpandableSection isExpanded={isExpanded} contentClassName="pt-0">
      <DataTableFilterCustom
        gridClassName="gap-3"
        filters={customFilters.map((filter) => ({
          ...filter,
          labelFormatter: (value: string) =>
            getResourcesFilterDisplayValue(
              `filter[${filter.key}]`,
              value,
              providers,
            ),
        }))}
        hideClearButton
        mode={DATA_TABLE_FILTER_MODE.BATCH}
        onBatchChange={setPending}
        getFilterValue={getFilterValue}
      />
    </ExpandableSection>
  ) : null;

  const appliedSummary = (
    <FilterSummaryStrip
      chips={appliedFilterChips}
      onRemove={removeAppliedAndApply}
      trailingContent={
        <ClearFiltersButton
          showCount
          onClear={clearAndApply}
          pendingCount={appliedCount}
        />
      }
    />
  );

  const pendingSummary = (
    <FilterSummaryStrip
      chips={pendingFilterChips}
      onRemove={handleChipRemove}
      trailingContent={
        <ApplyFiltersButton
          hasChanges={hasChanges}
          changeCount={changeCount}
          onApply={applyAll}
          onDiscard={discardAll}
        />
      }
    />
  );

  return (
    <BatchFiltersLayout
      testIdPrefix="resources"
      controls={
        <>
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
              selectedProviderTypes={getFilterValue(
                "filter[provider_type__in]",
              )}
            />
          </div>
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
        </>
      }
      expandedFilters={expandedFilters}
      expandedFiltersVisible={isExpanded}
      appliedSummary={appliedSummary}
      pendingSummary={pendingSummary}
      showAppliedRow={showAppliedRow}
      showPendingRow={showPendingRow}
    />
  );
};
