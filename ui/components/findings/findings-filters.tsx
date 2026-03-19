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

/**
 * Maps raw filter param keys (e.g. "filter[severity__in]") to human-readable labels.
 * Used to render chips in the FilterSummaryStrip.
 */
const FILTER_KEY_LABELS: Record<string, string> = {
  "filter[provider_type__in]": "Provider",
  "filter[provider_id__in]": "Account",
  "filter[severity__in]": "Severity",
  "filter[status__in]": "Status",
  "filter[delta__in]": "Delta",
  "filter[region__in]": "Region",
  "filter[service__in]": "Service",
  "filter[resource_type__in]": "Resource Type",
  "filter[category__in]": "Category",
  "filter[resource_groups__in]": "Resource Group",
  "filter[scan__in]": "Scan ID",
  "filter[inserted_at]": "Date",
  "filter[muted]": "Muted",
};

/**
 * Maps raw status values to human-readable display strings.
 */
const STATUS_DISPLAY: Record<string, string> = {
  PASS: "Pass",
  FAIL: "Fail",
  MANUAL: "Manual",
};

/**
 * Maps raw provider type values to human-readable display strings.
 */
const PROVIDER_TYPE_DISPLAY: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  kubernetes: "Kubernetes",
  googleworkspace: "Google Workspace",
  iac: "IaC",
  m365: "Microsoft 365",
  github: "GitHub",
  image: "Container Registry",
  oraclecloud: "Oracle Cloud",
  mongodbatlas: "MongoDB Atlas",
  alibabacloud: "Alibaba Cloud",
  cloudflare: "Cloudflare",
  openstack: "OpenStack",
};

/**
 * Formats a raw filter value into a human-readable display string.
 * - Provider types: uses PROVIDER_TYPE_DISPLAY map
 * - Status: PASS → Pass, FAIL → Fail, MANUAL → Manual
 * - Other values: capitalizes the first letter
 */
const formatFilterValue = (filterKey: string, value: string): string => {
  if (filterKey === "filter[provider_type__in]") {
    return PROVIDER_TYPE_DISPLAY[value] ?? value;
  }
  if (filterKey === "filter[status__in]") {
    return (
      STATUS_DISPLAY[value] ??
      value.charAt(0).toUpperCase() + value.slice(1).toLowerCase()
    );
  }
  // Default: capitalize first letter, lowercase rest
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
};

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
    clearAll,
    hasChanges,
    changeCount,
    getFilterValue,
  } = useFilterBatch({
    defaultParams: { "filter[muted]": "false" },
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
      values: completedScanIds,
      valueLabelMapping: scanDetails,
      index: 7,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;

  // Build FilterChip[] from pendingFilters — one chip per individual value, not per key
  const filterChips: FilterChip[] = [];
  Object.entries(pendingFilters).forEach(([key, values]) => {
    if (!values || values.length === 0) return;
    const label = FILTER_KEY_LABELS[key] ?? key;
    values.forEach((value) => {
      filterChips.push({
        key,
        label,
        value,
        displayValue: formatFilterValue(key, value),
      });
    });
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
          onClear={clearAll}
          pendingCount={
            Object.values(pendingFilters).filter((v) => v.length > 0).length
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
      <FilterSummaryStrip
        chips={filterChips}
        onRemove={handleChipRemove}
        onClearAll={clearAll}
      />

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
