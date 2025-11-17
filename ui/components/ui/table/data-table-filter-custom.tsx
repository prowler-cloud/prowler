"use client";

import { useSearchParams } from "next/navigation";

import { ComplianceScanInfo } from "@/components/compliance/compliance-header/compliance-scan-info";
import {
  Select,
  SelectAllItem,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { EntityInfoShort } from "@/components/ui/entities/entity-info-short";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { isScanEntity } from "@/lib/helper-filters";
import {
  FilterEntity,
  FilterOption,
  ProviderEntity,
  ScanEntity,
} from "@/types";

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

  // Render custom content for entity (scan or provider)
  const renderEntityContent = (entity: FilterEntity) => {
    if (isScanEntity(entity as ScanEntity)) {
      return <ComplianceScanInfo scan={entity as ScanEntity} />;
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
            <Select
              key={filter.key}
              multiple
              selectedValues={selectedValues}
              onMultiValueChange={(values) =>
                pushDropdownFilter(filter, values)
              }
              ariaLabel={filter.labelCheckboxGroup}
            >
              <SelectTrigger size="default">
                <SelectValue placeholder={filter.labelCheckboxGroup}>
                  {selectedValues.length > 0 && (
                    <span className="truncate">
                      {selectedValues.length === 1
                        ? // Show custom content for single selection
                          (() => {
                            const entity = getEntityForValue(
                              filter,
                              selectedValues[0],
                            );
                            return entity
                              ? renderEntityContent(entity)
                              : selectedValues[0];
                          })()
                        : // Show count for multiple selections
                          `${selectedValues.length} selected`}
                    </span>
                  )}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectAllItem allValues={filter.values}>
                  Select All
                </SelectAllItem>
                <SelectSeparator />
                {filter.values.map((value) => {
                  const entity = getEntityForValue(filter, value);
                  return (
                    <SelectItem key={value} value={value}>
                      {entity ? renderEntityContent(entity) : value}
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
          );
        })}
    </div>
  );
};
