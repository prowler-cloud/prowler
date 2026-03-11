"use client";

import { useSearchParams } from "next/navigation";
import type { ReactNode } from "react";

import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
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
import { isConnectionStatus, isGroupFilterEntity } from "@/lib/helper-filters";
import { FilterEntity, FilterOption, ProviderEntity } from "@/types";
import {
  GroupFilterEntity,
  ProviderConnectionStatus,
  ProviderProps,
} from "@/types/providers";

interface ProvidersFiltersProps {
  filters: FilterOption[];
  providers: ProviderProps[];
  actions?: ReactNode;
}

export const ProvidersFilters = ({
  filters,
  providers,
  actions,
}: ProvidersFiltersProps) => {
  const { updateFilter } = useUrlFilters();
  const searchParams = useSearchParams();

  const sortedFilters = [...filters].sort((a, b) => {
    if (a.index !== undefined && b.index !== undefined)
      return a.index - b.index;
    if (a.index !== undefined) return -1;
    if (b.index !== undefined) return 1;
    return 0;
  });

  const getSelectedValues = (filter: FilterOption): string[] => {
    const filterKey = filter.key.startsWith("filter[")
      ? filter.key
      : `filter[${filter.key}]`;
    const paramValue = searchParams.get(filterKey);
    if (!paramValue && filter.defaultToSelectAll) return filter.values;
    return paramValue ? paramValue.split(",") : [];
  };

  const pushDropdownFilter = (filter: FilterOption, values: string[]) => {
    const allSelected =
      filter.values.length > 0 && values.length === filter.values.length;
    if (filter.defaultToSelectAll && allSelected) {
      updateFilter(filter.key, null);
      return;
    }
    updateFilter(filter.key, values.length > 0 ? values : null);
  };

  const getEntityForValue = (
    filter: FilterOption,
    value: string,
  ): FilterEntity | undefined => {
    if (!filter.valueLabelMapping) return undefined;
    const entry = filter.valueLabelMapping.find((mapping) => mapping[value]);
    return entry ? entry[value] : undefined;
  };

  const getBadgeLabel = (
    entity: FilterEntity | undefined,
    value: string,
  ): string => {
    if (!entity) return value;
    if (isConnectionStatus(entity)) {
      return (entity as ProviderConnectionStatus).label;
    }
    if (isGroupFilterEntity(entity)) {
      return (entity as GroupFilterEntity).name || value;
    }
    const providerEntity = entity as ProviderEntity;
    return providerEntity.alias || providerEntity.uid || value;
  };

  const renderEntityContent = (entity: FilterEntity) => {
    if (isConnectionStatus(entity)) {
      return <span>{(entity as ProviderConnectionStatus).label}</span>;
    }
    if (isGroupFilterEntity(entity)) {
      return <span>{(entity as GroupFilterEntity).name}</span>;
    }
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

  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="min-w-[200px] flex-1 md:max-w-[280px]">
        <ProviderTypeSelector providers={providers} />
      </div>
      {sortedFilters.map((filter) => {
        const selectedValues = getSelectedValues(filter);
        return (
          <div key={filter.key} className="max-w-[240px] min-w-[180px] flex-1">
            <MultiSelect
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
          </div>
        );
      })}
      <ClearFiltersButton showCount />
      {actions && <div className="ml-auto flex flex-wrap gap-4">{actions}</div>}
    </div>
  );
};
