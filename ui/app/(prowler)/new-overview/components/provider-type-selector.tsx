"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

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

  const currentProvider = searchParams.get("filter[provider_type]") || "";
  const [open, setOpen] = useState(false);

  const handleValueChange = (value: string) => {
    const params = new URLSearchParams(searchParams.toString());

    // Update provider_type
    if (value) {
      params.set("filter[provider_type]", value);
    } else {
      params.delete("filter[provider_type]");
    }

    // Auto-select account(s) based on the chosen provider type
    if (value) {
      const candidates = providers.filter(
        (p) => p.attributes.connection?.connected && p.attributes.provider === (value as ProviderType),
      );

      if (candidates.length === 1) {
        // If there is only one connected account for this type, select it
        params.set("filter[provider_id__in]", candidates[0].id);
      } else {
        // Otherwise, clear existing account selection to avoid invalid combinations
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
  const selectedValue = availableTypes.includes(currentProvider as ProviderType)
    ? currentProvider
    : "";

  return (
    <Select
      allowDeselect
      value={selectedValue}
      onValueChange={handleValueChange}
      open={open}
      onOpenChange={setOpen}
    >
      <SelectTrigger>
        <SelectValue
          placeholder="All providers"
          aria-label="Select a provider type"
        >
          {currentProvider &&
            PROVIDER_DATA[currentProvider as ProviderType] && (
              <span className="flex items-center gap-2">
                {PROVIDER_DATA[currentProvider as ProviderType].icon}
                <span>
                  {PROVIDER_DATA[currentProvider as ProviderType].label}
                </span>
              </span>
            )}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {availableTypes.map((providerType) => (
          <SelectItem
            key={providerType}
            value={providerType}
            onPointerDown={(e) => {
              if (selectedValue === providerType) {
                e.preventDefault();
                handleValueChange("");
                setOpen(false);
              }
            }}
          >
            {PROVIDER_DATA[providerType].icon}
            <span>{PROVIDER_DATA[providerType].label}</span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
