"use client";

import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";

import { ApplyFiltersButton } from "@/components/filters/apply-filters-button";
import { BatchFiltersLayout } from "@/components/filters/batch-filters-layout";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { CustomDatePicker } from "@/components/filters/custom-date-picker";
import { filterFindings } from "@/components/filters/data-filters";
import {
  FilterChip,
  FilterSummaryStrip,
} from "@/components/filters/filter-summary-strip";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/shadcn/expandable-section";
import { DataTableFilterCustom } from "@/components/shadcn/table/data-table-filter-custom";
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
  /** Provider data for provider/account filter controls. */
  providers: ProviderProps[];
  completedScanIds: string[];
  scanDetails: { [key: string]: ScanEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueCategories: string[];
  uniqueGroups: string[];
  trailingControls?: ReactNode;
  variant?: "default" | "alerts-edit";
}

interface FindingsFilterBatchControlsProps extends FindingsFiltersProps {
  appliedFilters: Record<string, string[]>;
  pendingFilters: Record<string, string[]>;
  changedFilters: Record<string, string[]>;
  setPending: (filterKey: string, values: string[]) => void;
  applyAll?: () => void;
  discardAll?: () => void;
  clearAndApply?: () => void;
  removeAppliedAndApply?: (filterKey: string, value?: string) => void;
  hasChanges?: boolean;
  changeCount?: number;
  getFilterValue: (filterKey: string) => string[];
  showSummaries?: boolean;
}

const countVisibleFilterKeys = (filters: Record<string, string[]>): number =>
  Object.entries(filters).filter(([key, values]) => {
    if (!values || values.length === 0) return false;
    if (key === "filter[muted]") return false;
    return true;
  }).length;

const FILTER_CONTROL_COLUMN_CLASS =
  "min-w-0 flex-none basis-full sm:basis-[calc((100%_-_0.75rem)/2)] lg:basis-[calc((100%_-_1.5rem)/3)] xl:basis-[calc((100%_-_2.25rem)/4)] 2xl:basis-[calc((100%_-_3rem)/5)]";
const FILTER_GRID_ITEM_CLASS = "min-w-0";

export const FindingsFilterBatchControls = ({
  providers,
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueCategories,
  uniqueGroups,
  trailingControls,
  appliedFilters,
  pendingFilters,
  changedFilters,
  setPending,
  applyAll,
  discardAll,
  clearAndApply,
  removeAppliedAndApply,
  hasChanges = false,
  changeCount = 0,
  getFilterValue,
  showSummaries = true,
  variant = "default",
}: FindingsFilterBatchControlsProps) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const isAlertsEdit = variant === "alerts-edit";

  // Custom filters for the expandable section.
  const customFilters = [
    ...filterFindings
      .filter((filter) => !isAlertsEdit || filter.key !== FilterType.STATUS)
      .map((filter) => ({
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
    ...(isAlertsEdit
      ? []
      : [
          {
            key: FilterType.SCAN,
            labelCheckboxGroup: "Scan ID",
            values: completedScanIds,
            width: "wide" as const,
            valueLabelMapping: scanDetails,
            labelFormatter: (value: string) =>
              getFindingsFilterDisplayValue(
                `filter[${FilterType.SCAN}]`,
                value,
                {
                  providers,
                  scans: scanDetails,
                },
              ),
            index: 7,
          },
        ]),
  ];

  const hasCustomFilters = customFilters.length > 0;

  const appliedFilterChips: FilterChip[] = buildFindingsFilterChips(
    appliedFilters,
    {
      providers,
      scans: scanDetails,
    },
  );
  const pendingFilterChips: FilterChip[] = buildFindingsFilterChips(
    changedFilters,
    {
      providers,
      scans: scanDetails,
    },
  );
  const appliedCount = countVisibleFilterKeys(appliedFilters);
  const showAppliedRow = appliedFilterChips.length > 0;
  const showPendingRow = hasChanges;

  // Handler for removing a single chip: update the pending filter to remove that value.
  // setPending handles both "filter[key]" and "key" formats internally.
  const handleChipRemove = (filterKey: string, value?: string) => {
    if (value === undefined) {
      setPending(filterKey, []);
      return;
    }

    const currentValues = pendingFilters[filterKey] ?? [];
    const nextValues = currentValues.filter((v) => v !== value);
    setPending(filterKey, nextValues);
  };

  // For the date picker, read from pendingFilters
  const pendingDateValues = pendingFilters["filter[inserted_at]"];
  const pendingDateValue =
    pendingDateValues && pendingDateValues.length > 0
      ? pendingDateValues[0]
      : undefined;

  const providerAccountControls = (className: string) => (
    <ProviderAccountSelectors
      providers={providers}
      mode="batch"
      selectedProviderTypes={getFilterValue("filter[provider_type__in]")}
      selectedAccounts={getFilterValue("filter[provider_id__in]")}
      onBatchChange={setPending}
      providerSelectorClassName={className}
      accountSelectorClassName={className}
    />
  );

  const alertEditFilterGrid = hasCustomFilters ? (
    <DataTableFilterCustom
      gridClassName="w-full gap-3 xl:grid-cols-3 2xl:grid-cols-3"
      filters={customFilters}
      prependElement={providerAccountControls(FILTER_GRID_ITEM_CLASS)}
      hideClearButton
      mode={DATA_TABLE_FILTER_MODE.BATCH}
      onBatchChange={setPending}
      getFilterValue={getFilterValue}
    />
  ) : null;

  const expandedFilters =
    hasCustomFilters && !isAlertsEdit ? (
      <ExpandableSection isExpanded={isExpanded} contentClassName="pt-0">
        <DataTableFilterCustom
          gridClassName="gap-3"
          filters={customFilters}
          prependElement={
            isAlertsEdit ? undefined : (
              <CustomDatePicker
                onBatchChange={(filterKey, value) =>
                  setPending(filterKey, value ? [value] : [])
                }
                value={pendingDateValue}
              />
            )
          }
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
      onRemove={removeAppliedAndApply ?? (() => undefined)}
      trailingContent={
        <ClearFiltersButton
          showCount
          onClear={clearAndApply ?? (() => undefined)}
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
          onApply={applyAll ?? (() => undefined)}
          onDiscard={discardAll ?? (() => undefined)}
        />
      }
    />
  );

  return (
    <BatchFiltersLayout
      testIdPrefix="findings"
      controlsClassName="gap-3"
      controls={
        isAlertsEdit ? (
          alertEditFilterGrid
        ) : (
          <>
            {providerAccountControls(FILTER_CONTROL_COLUMN_CLASS)}
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
            {trailingControls}
          </>
        )
      }
      expandedFilters={expandedFilters}
      expandedFiltersVisible={isExpanded}
      appliedSummary={showSummaries ? appliedSummary : null}
      pendingSummary={showSummaries ? pendingSummary : null}
      showAppliedRow={showSummaries && showAppliedRow}
      showPendingRow={showSummaries && showPendingRow}
    />
  );
};

export const FindingsFilters = (props: FindingsFiltersProps) => {
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
  } = useFilterBatch({
    defaultParams: { "filter[muted]": "false" },
  });

  return (
    <FindingsFilterBatchControls
      {...props}
      appliedFilters={appliedFilters}
      pendingFilters={pendingFilters}
      changedFilters={changedFilters}
      setPending={setPending}
      applyAll={applyAll}
      discardAll={discardAll}
      clearAndApply={clearAndApply}
      removeAppliedAndApply={removeAppliedAndApply}
      hasChanges={hasChanges}
      changeCount={changeCount}
      getFilterValue={getFilterValue}
    />
  );
};
