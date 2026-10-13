"use client";

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { SearchInput } from "@/components/shadcn/search-input/search-input";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { getProviderDisplayName } from "@/types/providers";

import {
  REGISTRY_CAPABILITY_LABELS,
  REGISTRY_CATALOG_CAPABILITY,
  REGISTRY_MARKETPLACE_SORT,
  type RegistryCatalogCapability,
  type RegistryExplorerFilters,
  type RegistryMarketplaceSort,
} from "./registry-explorer.model";

interface RegistryToolbarProps {
  filters: RegistryExplorerFilters;
  onFiltersChange: (filters: RegistryExplorerFilters) => void;
  onSortChange: (sort: RegistryMarketplaceSort) => void;
  providers: string[];
  resultsCount: number;
  sort: RegistryMarketplaceSort;
}

export function RegistryToolbar({
  filters,
  onFiltersChange,
  onSortChange,
  providers,
  resultsCount,
  sort,
}: RegistryToolbarProps) {
  const activeCount =
    Number(Boolean(filters.providers?.length)) +
    Number(Boolean(filters.capabilities?.length)) +
    Number(Boolean(filters.search));
  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="w-full sm:w-64">
        <SearchInput
          aria-label="Search artifacts"
          placeholder="Search artifacts..."
          value={filters.search ?? ""}
          onChange={(event) =>
            onFiltersChange({ ...filters, search: event.target.value })
          }
          onClear={() => onFiltersChange({ ...filters, search: undefined })}
        />
      </div>
      <div className="w-full sm:w-56">
        <MultiSelect
          values={filters.providers ?? []}
          onValuesChange={(values) =>
            onFiltersChange({ ...filters, providers: values })
          }
        >
          <MultiSelectTrigger aria-label="Filter by provider">
            <MultiSelectValue placeholder="All providers" />
          </MultiSelectTrigger>
          <MultiSelectContent
            search={{
              placeholder: "Search providers...",
              emptyMessage: "No providers found.",
            }}
          >
            <MultiSelectSelectAll>Select All</MultiSelectSelectAll>
            <MultiSelectSeparator />
            {providers.map((provider) => (
              <MultiSelectItem
                key={provider}
                value={provider}
                badgeLabel={getProviderDisplayName(provider)}
              >
                <ProviderTypeIcon size={20} type={provider} />
                {getProviderDisplayName(provider)}
              </MultiSelectItem>
            ))}
          </MultiSelectContent>
        </MultiSelect>
      </div>
      <div className="w-full sm:w-52">
        <MultiSelect
          values={filters.capabilities ?? []}
          onValuesChange={(values) =>
            onFiltersChange({
              ...filters,
              capabilities: values as RegistryCatalogCapability[],
            })
          }
        >
          <MultiSelectTrigger aria-label="Filter by capability">
            <MultiSelectValue placeholder="All capabilities" />
          </MultiSelectTrigger>
          <MultiSelectContent>
            {Object.values(REGISTRY_CATALOG_CAPABILITY).map((capability) => (
              <MultiSelectItem key={capability} value={capability}>
                {REGISTRY_CAPABILITY_LABELS[capability]}
              </MultiSelectItem>
            ))}
          </MultiSelectContent>
        </MultiSelect>
      </div>
      <div className="w-full sm:w-48">
        <Select
          value={sort}
          onValueChange={(value) =>
            onSortChange(value as RegistryMarketplaceSort)
          }
        >
          <SelectTrigger aria-label="Sort artifacts">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={REGISTRY_MARKETPLACE_SORT.NAME}>
              Name (A–Z)
            </SelectItem>
            <SelectItem value={REGISTRY_MARKETPLACE_SORT.DOWNLOADS}>
              Most downloaded
            </SelectItem>
          </SelectContent>
        </Select>
      </div>
      <ClearFiltersButton
        ariaLabel="Clear filters"
        showCount
        pendingCount={activeCount}
        onClear={() => {
          onFiltersChange({});
        }}
      />
      <p
        aria-live="polite"
        className="text-text-neutral-secondary ml-auto text-sm"
      >
        {resultsCount} artifact{resultsCount === 1 ? "" : "s"}
      </p>
    </div>
  );
}
