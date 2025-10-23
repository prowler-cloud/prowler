"use client";

import { useRouter, useSearchParams } from "next/navigation";

import {
  AWSProviderBadge,
  AzureProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
} from "@/components/icons/providers-badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import type { ProviderProps, ProviderType } from "@/types/providers";

const PROVIDER_ICON: Record<ProviderType, React.ReactNode> = {
  aws: <AWSProviderBadge width={18} height={18} />,
  azure: <AzureProviderBadge width={18} height={18} />,
  gcp: <GCPProviderBadge width={18} height={18} />,
  kubernetes: <KS8ProviderBadge width={18} height={18} />,
  m365: <M365ProviderBadge width={18} height={18} />,
  github: <GitHubProviderBadge width={18} height={18} />,
};

interface AccountsSelectorProps {
  providers: ProviderProps[];
}

export function AccountsSelector({ providers }: AccountsSelectorProps) {
  const router = useRouter();
  const searchParams = useSearchParams();

  const current = searchParams.get("filter[provider_id__in]") || "";
  const selectedTypes = searchParams.get("filter[provider_type__in]") || "";
  const selectedTypesList = selectedTypes
    ? selectedTypes.split(",").filter(Boolean)
    : [];
  const selectedIds = current ? current.split(",").filter(Boolean) : [];
  const visibleProviders = providers
    .filter((p) => p.attributes.connection?.connected)
    .filter((p) =>
      selectedTypesList.length > 0
        ? selectedTypesList.includes(p.attributes.provider)
        : true,
    );

  const handleMultiValueChange = (ids: string[]) => {
    const params = new URLSearchParams(searchParams.toString());
    if (ids.length > 0) {
      params.set("filter[provider_id__in]", ids.join(","));
    } else {
      params.delete("filter[provider_id__in]");
    }

    // Auto-deselect provider types that no longer have any selected accounts
    if (selectedTypesList.length > 0) {
      // Get provider types of currently selected accounts
      const selectedProviders = providers.filter((p) => ids.includes(p.id));
      const selectedProviderTypes = new Set(
        selectedProviders.map((p) => p.attributes.provider),
      );

      // Keep only provider types that still have selected accounts
      const remainingProviderTypes = selectedTypesList.filter((type) =>
        selectedProviderTypes.has(type as ProviderType),
      );

      // Update provider_type__in filter
      if (remainingProviderTypes.length > 0) {
        params.set(
          "filter[provider_type__in]",
          remainingProviderTypes.join(","),
        );
      } else {
        params.delete("filter[provider_type__in]");
      }
    }

    router.push(`?${params.toString()}`, { scroll: false });
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null; // placeholder visible
    if (selectedIds.length === 1) {
      const p = providers.find((pr) => pr.id === selectedIds[0]);
      const name = p ? p.attributes.alias || p.attributes.uid : selectedIds[0];
      return <span className="truncate">{name}</span>;
    }
    return (
      <span className="truncate">{selectedIds.length} accounts selected</span>
    );
  };

  return (
    <Select
      multiple
      selectedValues={selectedIds}
      onMultiValueChange={handleMultiValueChange}
    >
      <SelectTrigger>
        <SelectValue placeholder="All accounts">{selectedLabel()}</SelectValue>
      </SelectTrigger>
      <SelectContent align="start">
        {visibleProviders.map((p) => {
          const id = p.id;
          const displayName = p.attributes.alias || p.attributes.uid;
          const icon = PROVIDER_ICON[p.attributes.provider as ProviderType];
          return (
            <SelectItem key={id} value={id}>
              {icon}
              <span className="truncate">{displayName}</span>
            </SelectItem>
          );
        })}
      </SelectContent>
    </Select>
  );
}
