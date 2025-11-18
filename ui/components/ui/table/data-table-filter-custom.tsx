"use client";

import { useSearchParams } from "next/navigation";

import { ComplianceScanInfo } from "@/components/compliance/compliance-header/compliance-scan-info";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { EntityInfoShort } from "@/components/ui/entities/entity-info-short";
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
}

export const DataTableFilterCustom = ({
  filters,
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
      <EntityInfoShort
        cloudProvider={providerEntity.provider}
        entityAlias={providerEntity.alias ?? undefined}
        entityId={providerEntity.uid}
        hideCopyButton
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

  const getSelectedValues = (key: string): string[] => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    const paramValue = searchParams.get(filterKey);
    return paramValue ? paramValue.split(",") : [];
  };

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
      {sortedFilters()
        .filter((filter) => filter.values.length > 1)
        .map((filter) => {
          const selectedValues = getSelectedValues(filter.key);

          return (
            <MultiSelect
              key={filter.key}
              values={selectedValues}
              onValuesChange={(values) => pushDropdownFilter(filter, values)}
            >
              <MultiSelectTrigger size="default">
                <MultiSelectValue placeholder={filter.labelCheckboxGroup} />
              </MultiSelectTrigger>
              <MultiSelectContent
                search={{
                  placeholder: `Search ${filter.labelCheckboxGroup.toLowerCase()}...`,
                  emptyMessage: "No results found",
                }}
              >
                <MultiSelectSelectAll allValues={filter.values}>
                  Select All
                </MultiSelectSelectAll>
                <MultiSelectSeparator />
                {filter.values.map((value) => {
                  const entity = getEntityForValue(filter, value);
                  return (
                    <MultiSelectItem
                      key={value}
                      value={value}
                      badgeLabel={getBadgeLabel(entity, value)}
                    >
                      {entity ? renderEntityContent(entity) : value}
                    </MultiSelectItem>
                  );
                })}
              </MultiSelectContent>
            </MultiSelect>
          );
        })}
    </div>
  );
};
