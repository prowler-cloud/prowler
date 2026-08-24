import { Checkbox } from "@/components/shadcn/checkbox";
import { Input } from "@/components/shadcn/input/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { TreeView } from "@/components/shadcn/tree-view";
import { getProviderDisplayName } from "@/types/providers";
import type {
  RegistryCatalogArtifact,
  RegistryTenantArtifact,
} from "@/types/registry";
import type { TreeDataItem } from "@/types/tree";

import {
  REGISTRY_CATALOG_CAPABILITY,
  type RegistryCatalogCapability,
  type RegistryExplorerFilters,
} from "./registry-explorer.model";

interface RegistryNavigationProps {
  artifacts: RegistryCatalogArtifact[];
  expandedIds: string[];
  filters: RegistryExplorerFilters;
  onExpandedChange: (ids: string[]) => void;
  onFiltersChange: (filters: RegistryExplorerFilters) => void;
  onSelectedIdChange: (id: string) => void;
  providers: string[];
  selectedId: string;
  tenantArtifacts: RegistryTenantArtifact[];
}

const capabilities = Object.values(REGISTRY_CATALOG_CAPABILITY);
const capabilityLabels = {
  provider: "Provider",
  checks: "Checks",
  compliance: "Compliance",
} as const satisfies Record<RegistryCatalogCapability, string>;

function leaf(
  collection: string,
  artifact: RegistryCatalogArtifact | RegistryTenantArtifact,
): TreeDataItem {
  return {
    id: `leaf:${collection}:${encodeURIComponent(artifact.normalizedName)}`,
    name:
      ("name" in artifact ? artifact.name : undefined) ??
      artifact.normalizedName,
  };
}

export function RegistryNavigation({
  artifacts,
  expandedIds,
  filters,
  onExpandedChange,
  onFiltersChange,
  onSelectedIdChange,
  providers,
  selectedId,
  tenantArtifacts,
}: RegistryNavigationProps) {
  const selectedCapabilities = filters.capabilities ?? [];
  const data: TreeDataItem[] = [
    {
      id: "root:available",
      name: "Available artifacts",
      children: [
        ...providers.map((provider) => ({
          id: `group:${provider}`,
          name: getProviderDisplayName(provider),
          children: artifacts
            .filter((artifact) => artifact.providers.includes(provider))
            .map((artifact) => leaf(provider, artifact)),
        })),
        {
          id: "group:multi-provider",
          name: "Multi-provider",
          children: artifacts
            .filter((artifact) => artifact.providers.length > 1)
            .map((artifact) => leaf("multi-provider", artifact)),
        },
      ],
    },
    {
      id: "root:my-artifacts",
      name: "My artifacts",
      children: tenantArtifacts.map((artifact) =>
        leaf("my-artifacts", artifact),
      ),
    },
  ];
  const updateExpanded = (ids: string[]) => {
    const selected =
      ids.find((id) => !expandedIds.includes(id)) ??
      expandedIds.find((id) => !ids.includes(id));
    onExpandedChange(ids);
    if (selected) onSelectedIdChange(selected);
  };
  const updateCapability = (
    capability: RegistryCatalogCapability,
    checked: boolean,
  ) =>
    onFiltersChange({
      ...filters,
      capabilities: checked
        ? [...selectedCapabilities, capability]
        : selectedCapabilities.filter((value) => value !== capability),
    });

  return (
    <nav aria-label="Registry explorer" className="space-y-4">
      <Input
        aria-label="Search Registry artifacts"
        placeholder="Search artifacts"
        value={filters.search ?? ""}
        onChange={(event) =>
          onFiltersChange({ ...filters, search: event.target.value })
        }
      />
      <Select
        value={filters.provider ?? "all"}
        onValueChange={(provider) =>
          onFiltersChange({
            ...filters,
            provider: provider === "all" ? undefined : provider,
          })
        }
      >
        <SelectTrigger aria-label="Filter by provider" size="sm">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All providers</SelectItem>
          {providers.map((provider) => (
            <SelectItem key={provider} value={provider}>
              {getProviderDisplayName(provider)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {capabilities.map((capability) => (
        <label key={capability} className="flex items-center gap-2 text-sm">
          <Checkbox
            checked={selectedCapabilities.includes(capability)}
            onCheckedChange={(checked) =>
              updateCapability(capability, checked === true)
            }
          />
          {capabilityLabels[capability]}
        </label>
      ))}
      <TreeView
        data={data}
        enableSelectChildren={false}
        expandedIds={expandedIds}
        onExpandedChange={updateExpanded}
        onSelectionChange={(ids) =>
          onSelectedIdChange(ids.at(-1) ?? "root:available")
        }
        selectedIds={[selectedId]}
      />
    </nav>
  );
}
