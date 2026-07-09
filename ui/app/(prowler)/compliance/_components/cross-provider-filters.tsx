"use client";

import { useSearchParams } from "next/navigation";

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
import { PROVIDER_DISPLAY_NAMES, type ProviderType } from "@/types/providers";

export interface CrossProviderAccountOption {
  id: string;
  label: string;
  type: ProviderType;
}

export interface CrossProviderGroupOption {
  id: string;
  name: string;
}

interface CrossProviderFiltersProps {
  /** Provider types offered by the visible universal frameworks. */
  providerTypes: readonly ProviderType[];
  providerAccounts: CrossProviderAccountOption[];
  providerGroups: CrossProviderGroupOption[];
  /** Region options; the filter is hidden when empty. */
  regions: string[];
}

interface UrlMultiSelectProps {
  filterKey: string;
  placeholder: string;
  options: { value: string; label: string }[];
}

const UrlMultiSelect = ({
  filterKey,
  placeholder,
  options,
}: UrlMultiSelectProps) => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();

  const values =
    searchParams.get(`filter[${filterKey}]`)?.split(",").filter(Boolean) ?? [];

  return (
    <div className="w-full sm:max-w-[280px] sm:min-w-[180px] sm:flex-1">
      <MultiSelect
        values={values}
        onValuesChange={(nextValues) => updateFilter(filterKey, nextValues)}
      >
        <MultiSelectTrigger size="default">
          <MultiSelectValue placeholder={placeholder} />
        </MultiSelectTrigger>
        <MultiSelectContent search={options.length > 8} width="wide">
          <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
          <MultiSelectSeparator />
          {options.map((option) => (
            <MultiSelectItem key={option.value} value={option.value}>
              {option.label}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};

export const CrossProviderFilters = ({
  providerTypes,
  providerAccounts,
  providerGroups,
  regions,
}: CrossProviderFiltersProps) => {
  return (
    <div className="flex flex-wrap items-center gap-4">
      <UrlMultiSelect
        filterKey="provider_type__in"
        placeholder="All Providers"
        options={providerTypes.map((type) => ({
          value: type,
          label: PROVIDER_DISPLAY_NAMES[type],
        }))}
      />
      <UrlMultiSelect
        filterKey="provider_id__in"
        placeholder="All Accounts"
        options={providerAccounts.map((account) => ({
          value: account.id,
          label: account.label,
        }))}
      />
      <UrlMultiSelect
        filterKey="provider_groups__in"
        placeholder="All Groups"
        options={providerGroups.map((group) => ({
          value: group.id,
          label: group.name,
        }))}
      />
      {regions.length > 0 && (
        <UrlMultiSelect
          filterKey="region__in"
          placeholder="All Regions"
          options={regions.map((region) => ({ value: region, label: region }))}
        />
      )}
      <ClearFiltersButton showCount />
    </div>
  );
};
