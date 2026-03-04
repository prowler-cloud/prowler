"use client";

import { useSearchParams } from "next/navigation";

import { ComplianceScanInfo } from "@/components/compliance/compliance-header/compliance-scan-info";
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
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { isConnectionStatus, isScanEntity } from "@/lib/helper-filters";
import {
  FilterEntity,
  FilterOption,
  ProviderEntity,
  ScanEntity,
} from "@/types";
import { ProviderConnectionStatus } from "@/types/providers";

export interface DataTableFilterCustomProps {
  filters: FilterOption[];
  /** Optional element to render at the start of the filters grid */
  prependElement?: React.ReactNode;
  /** Hide the clear filters button and active badges (useful when parent manages this) */
  hideClearButton?: boolean;
}

export const DataTableFilterCustom = ({
  filters,
  prependElement,
  hideClearButton = false,
}: DataTableFilterCustomProps) => {
  const { updateFilter } = useUrlFilters();
  const searchParams = useSearchParams();

  // Helper function to get entity from valueLabelMapping
  const getEntityForValue = (
    filter: FilterOption,
    value: string,
  ): FilterEntity | undefined => {
    if (!filter.valueLabelMapping) return undefined;
    const entry = filter.valueLabelMapping.find((mapping) => mapping[value]);
    return entry ? entry[value] : undefined;
  };

  // Helper function to get badge label from entity
  const getBadgeLabel = (
    entity: FilterEntity | undefined,
    value: string,
  ): string => {
    if (!entity) return value;

    if (isScanEntity(entity as ScanEntity)) {
      const scanEntity = entity as ScanEntity;
      return (
        scanEntity.providerInfo?.alias || scanEntity.providerInfo?.uid || value
      );
    }
    if (isConnectionStatus(entity)) {
      const connectionStatus = entity as ProviderConnectionStatus;
      return connectionStatus.label;
    }
    // Provider entity
    const providerEntity = entity as ProviderEntity;
    return providerEntity.alias || providerEntity.uid || value;
  };

  // Render custom content for entity (scan, provider, or connection status)
  const renderEntityContent = (entity: FilterEntity) => {
    if (isScanEntity(entity as ScanEntity)) {
      return <ComplianceScanInfo scan={entity as ScanEntity} />;
    }
    if (isConnectionStatus(entity)) {
      const connectionStatus = entity as ProviderConnectionStatus;
      return <span>{connectionStatus.label}</span>;
    }
    // Provider entity
    const providerEntity = entity as ProviderEntity;
    return (
      <EntityInfo
        cloudProvider={providerEntity.provider}
        entityAlias={providerEntity.alias ?? undefined}
        entityId={providerEntity.uid}
        showCopyAction={false}
      />
    );
  };

  // Sort filters by index property, with fallback to original order for filters without index
  const sortedFilters = () => {
    return [...filters].sort((a, b) => {
      // If both have index, sort by index
      if (a.index !== undefined && b.index !== undefined) {
        return a.index - b.index;
      }
      // If only one has index, prioritize the one with index
      if (a.index !== undefined) return -1;
      if (b.index !== undefined) return 1;
      // If neither has index, maintain original order
      return 0;
    });
  };

  const pushDropdownFilter = (filter: FilterOption, values: string[]) => {
    // If this filter defaults to "all selected" and the user selected all items,
    // clear the URL param to represent "no specific filter" (i.e., all).
    const allSelected =
      filter.values.length > 0 && values.length === filter.values.length;

    if (filter.defaultToSelectAll && allSelected) {
      updateFilter(filter.key, null);
      return;
    }

    updateFilter(filter.key, values.length > 0 ? values : null);
  };

  const getSelectedValues = (filter: FilterOption): string[] => {
    const filterKey = filter.key.startsWith("filter[")
      ? filter.key
      : `filter[${filter.key}]`;
    const paramValue = searchParams.get(filterKey);

    // If defaultToSelectAll is true and no filter param exists,
    // treat it as "all selected" by returning all values
    if (!paramValue && filter.defaultToSelectAll) {
      return filter.values;
    }

    return paramValue ? paramValue.split(",") : [];
  };

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
      {prependElement}
      {sortedFilters().map((filter) => {
        const selectedValues = getSelectedValues(filter);

        return (
          <MultiSelect
            key={filter.key}
            values={selectedValues}
            onValuesChange={(values) => pushDropdownFilter(filter, values)}
          >
            <MultiSelectTrigger size="default">
              <MultiSelectValue placeholder={filter.labelCheckboxGroup} />
            </MultiSelectTrigger>
            <MultiSelectContent search={false}>
              <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
              <MultiSelectSeparator />
              {filter.values.map((value) => {
                const entity = getEntityForValue(filter, value);
                const displayLabel = filter.labelFormatter
                  ? filter.labelFormatter(value)
                  : value;
                return (
                  <MultiSelectItem
                    key={value}
                    value={value}
                    badgeLabel={getBadgeLabel(entity, displayLabel)}
                  >
                    {entity ? renderEntityContent(entity) : displayLabel}
                  </MultiSelectItem>
                );
              })}
            </MultiSelectContent>
          </MultiSelect>
        );
      })}
      {!hideClearButton && (
        <div className="flex items-center justify-start">
          <ClearFiltersButton />
        </div>
      )}
    </div>
  );
};
