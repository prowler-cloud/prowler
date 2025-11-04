"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { lazy, Suspense } from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { type ProviderProps, ProviderType } from "@/types/providers";

const AWSProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AWSProviderBadge,
  })),
);
const AzureProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AzureProviderBadge,
  })),
);
const GCPProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GCPProviderBadge,
  })),
);
const KS8ProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.KS8ProviderBadge,
  })),
);
const M365ProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.M365ProviderBadge,
  })),
);
const GitHubProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GitHubProviderBadge,
  })),
);
const IacProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.IacProviderBadge,
  })),
);
const OracleCloudProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OracleCloudProviderBadge,
  })),
);

type IconProps = { width: number; height: number };

const IconPlaceholder = ({ width, height }: IconProps) => (
  <div style={{ width, height }} />
);

const PROVIDER_DATA: Record<
  ProviderType,
  { label: string; icon: React.ComponentType<IconProps> }
> = {
  aws: {
    label: "Amazon Web Services",
    icon: AWSProviderBadge,
  },
  azure: {
    label: "Microsoft Azure",
    icon: AzureProviderBadge,
  },
  gcp: {
    label: "Google Cloud Platform",
    icon: GCPProviderBadge,
  },
  kubernetes: {
    label: "Kubernetes",
    icon: KS8ProviderBadge,
  },
  m365: {
    label: "Microsoft 365",
    icon: M365ProviderBadge,
  },
  github: {
    label: "GitHub",
    icon: GitHubProviderBadge,
  },
  iac: {
    label: "Infrastructure as Code",
    icon: IacProviderBadge,
  },
  oci: {
    label: "Oracle Cloud Infrastructure",
    icon: OracleCloudProviderBadge,
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

    // Clear account selection when changing provider types
    // User should manually select accounts if they want to filter by specific accounts
    params.delete("filter[provider_id__in]");

    router.push(`?${params.toString()}`, { scroll: false });
  };

  const availableTypes = Array.from(
    new Set(
      providers
        .filter((p) => p.attributes.connection?.connected)
        .map((p) => p.attributes.provider),
    ),
  ) as ProviderType[];

  const renderIcon = (providerType: ProviderType) => {
    const IconComponent = PROVIDER_DATA[providerType].icon;
    return (
      <Suspense fallback={<IconPlaceholder width={24} height={24} />}>
        <IconComponent width={24} height={24} />
      </Suspense>
    );
  };

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null; // placeholder visible
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0] as ProviderType;
      return (
        <span className="flex items-center gap-2">
          {renderIcon(providerType)}
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
    <div className="relative">
      <label
        htmlFor="provider-type-selector"
        className="sr-only"
        id="provider-type-label"
      >
        Filter by cloud provider type. Select one or more providers to view
        findings.
      </label>
      <Select
        multiple
        selectedValues={selectedTypes}
        onMultiValueChange={handleMultiValueChange}
        ariaLabel="Cloud provider type filter"
      >
        <SelectTrigger
          id="provider-type-selector"
          aria-labelledby="provider-type-label"
        >
          <SelectValue placeholder="All providers">
            {selectedLabel()}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {availableTypes.length > 0 ? (
            availableTypes.map((providerType) => (
              <SelectItem
                key={providerType}
                value={providerType}
                aria-label={`${PROVIDER_DATA[providerType].label} provider`}
              >
                <span aria-hidden="true">{renderIcon(providerType)}</span>
                <span>{PROVIDER_DATA[providerType].label}</span>
              </SelectItem>
            ))
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              No connected providers available
            </div>
          )}
        </SelectContent>
      </Select>
    </div>
  );
};
