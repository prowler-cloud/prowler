import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Button } from "@/components/shadcn/button/button";
import { SearchInput } from "@/components/shadcn/search-input/search-input";
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

const capabilityChips = [
  {
    capability: REGISTRY_CATALOG_CAPABILITY.CHECKS,
    label: REGISTRY_CAPABILITY_LABELS.checks,
  },
  {
    capability: REGISTRY_CATALOG_CAPABILITY.COMPLIANCE,
    label: REGISTRY_CAPABILITY_LABELS.compliance,
  },
  {
    // The provider chip filters by provider capability but is labeled in the plural.
    capability: REGISTRY_CATALOG_CAPABILITY.PROVIDER,
    label: `${REGISTRY_CAPABILITY_LABELS.provider}s`,
  },
] as const;

export function RegistryToolbar({
  filters,
  onFiltersChange,
  onSortChange,
  providers,
  resultsCount,
  sort,
}: RegistryToolbarProps) {
  const selectedCapabilities = filters.capabilities ?? [];

  const toggleCapability = (capability: RegistryCatalogCapability) =>
    onFiltersChange({
      ...filters,
      capabilities: selectedCapabilities.includes(capability)
        ? selectedCapabilities.filter((value) => value !== capability)
        : [...selectedCapabilities, capability],
    });

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="w-full sm:w-64">
        <SearchInput
          aria-label="Search artifacts"
          onChange={(event) =>
            onFiltersChange({ ...filters, search: event.target.value })
          }
          onClear={() => onFiltersChange({ ...filters, search: undefined })}
          placeholder="Search artifacts"
          value={filters.search ?? ""}
        />
      </div>
      <div className="w-full sm:w-48">
        <Select
          onValueChange={(provider) =>
            onFiltersChange({
              ...filters,
              provider: provider === "all" ? undefined : provider,
            })
          }
          value={filters.provider ?? "all"}
        >
          <SelectTrigger aria-label="Filter by provider" size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All providers</SelectItem>
            {providers.map((provider) => (
              <SelectItem key={provider} value={provider}>
                <span aria-hidden="true">
                  <ProviderTypeIcon size={24} type={provider} />
                </span>
                <span>{getProviderDisplayName(provider)}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="w-full sm:w-44">
        <Select
          onValueChange={(value) =>
            onSortChange(value as RegistryMarketplaceSort)
          }
          value={sort}
        >
          <SelectTrigger aria-label="Sort artifacts" size="sm">
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
      <div className="flex flex-wrap items-center gap-2">
        <Button
          aria-pressed={selectedCapabilities.length === 0}
          onClick={() => onFiltersChange({ ...filters, capabilities: [] })}
          size="sm"
          type="button"
          variant={selectedCapabilities.length === 0 ? "secondary" : "outline"}
        >
          All
        </Button>
        {capabilityChips.map(({ capability, label }) => (
          <Button
            aria-pressed={selectedCapabilities.includes(capability)}
            key={capability}
            onClick={() => toggleCapability(capability)}
            size="sm"
            type="button"
            variant={
              selectedCapabilities.includes(capability)
                ? "secondary"
                : "outline"
            }
          >
            {label}
          </Button>
        ))}
      </div>
      <p className="text-text-neutral-secondary ml-auto text-sm">
        {resultsCount} artifact{resultsCount === 1 ? "" : "s"}
      </p>
    </div>
  );
}
