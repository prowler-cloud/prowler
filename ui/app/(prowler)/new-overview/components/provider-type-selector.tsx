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
import { type ProviderProps, ProviderType } from "@/types/providers";

const PROVIDER_DATA: Record<
  ProviderType,
  { label: string; icon: React.ReactNode }
> = {
  aws: {
    label: "Amazon Web Services",
    icon: <AWSProviderBadge width={24} height={24} />,
  },
  azure: {
    label: "Microsoft Azure",
    icon: <AzureProviderBadge width={24} height={24} />,
  },
  gcp: {
    label: "Google Cloud Platform",
    icon: <GCPProviderBadge width={24} height={24} />,
  },
  kubernetes: {
    label: "Kubernetes",
    icon: <KS8ProviderBadge width={24} height={24} />,
  },
  m365: {
    label: "Microsoft 365",
    icon: <M365ProviderBadge width={24} height={24} />,
  },
  github: {
    label: "GitHub",
    icon: <GitHubProviderBadge width={24} height={24} />,
  },
};

type ProviderTypeSelectorProps = {
  providers: ProviderProps[];
};

export const ProviderTypeSelector = ({
  providers,
}: ProviderTypeSelectorProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const currentProviders = searchParams.get("filter[provider_type__in]") || "";
  const selectedTypes = currentProviders
    ? currentProviders.split(",").filter(Boolean)
    : [];

  const handleMultiValueChange = (values: string[]) => {
    const params = new URLSearchParams(searchParams.toString());

    // Update provider_type__in
    if (values.length > 0) {
      params.set("filter[provider_type__in]", values.join(","));
    } else {
      params.delete("filter[provider_type__in]");
    }

    // Auto-select account(s) based on the chosen provider types
    if (values.length > 0) {
      const candidates = providers.filter(
        (p) =>
          p.attributes.connection?.connected &&
          values.includes(p.attributes.provider),
      );

      if (candidates.length === 1) {
        // If there is only one connected account for selected types, select it
        params.set("filter[provider_id__in]", candidates[0].id);
      } else if (candidates.length > 1) {
        // Multiple candidates: auto-select all accounts from selected provider types
        params.set(
          "filter[provider_id__in]",
          candidates.map((c) => c.id).join(","),
        );
      } else {
        // No candidates: clear account selection
        params.delete("filter[provider_id__in]");
      }
    } else {
      // Clearing provider type should also clear selected accounts
      params.delete("filter[provider_id__in]");
    }

    router.push(`?${params.toString()}`, { scroll: false });
  };

  const availableTypes = Array.from(
    new Set(
      providers
        .filter((p) => p.attributes.connection?.connected)
        .map((p) => p.attributes.provider),
    ),
  ) as ProviderType[];

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null; // placeholder visible
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0] as ProviderType;
      return (
        <span className="flex items-center gap-2">
          {PROVIDER_DATA[providerType].icon}
          <span>{PROVIDER_DATA[providerType].label}</span>
        </span>
      );
    }
    return (
      <span className="truncate">
        {selectedTypes.length} providers selected
      </span>
    );
  };

  return (
    <Select
      multiple
      selectedValues={selectedTypes}
      onMultiValueChange={handleMultiValueChange}
    >
      <SelectTrigger>
        <SelectValue
          placeholder="All providers"
          aria-label="Select provider types"
        >
          {selectedLabel()}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {availableTypes.map((providerType) => (
          <SelectItem key={providerType} value={providerType}>
            {PROVIDER_DATA[providerType].icon}
            <span>{PROVIDER_DATA[providerType].label}</span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
