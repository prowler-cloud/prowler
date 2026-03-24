"use client";

import { useSearchParams } from "next/navigation";
import { type ComponentType, lazy, Suspense } from "react";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
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
const ImageProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.ImageProviderBadge,
  })),
);
const OracleCloudProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OracleCloudProviderBadge,
  })),
);
const MongoDBAtlasProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.MongoDBAtlasProviderBadge,
  })),
);
const AlibabaCloudProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.AlibabaCloudProviderBadge,
  })),
);
const CloudflareProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.CloudflareProviderBadge,
  })),
);
const OpenStackProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.OpenStackProviderBadge,
  })),
);
const GoogleWorkspaceProviderBadge = lazy(() =>
  import("@/components/icons/providers-badge").then((m) => ({
    default: m.GoogleWorkspaceProviderBadge,
  })),
);

type IconProps = { width: number; height: number };

const IconPlaceholder = ({ width, height }: IconProps) => (
  <div style={{ width, height }} />
);

const PROVIDER_DATA: Record<
  ProviderType,
  { label: string; icon: ComponentType<IconProps> }
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
  googleworkspace: {
    label: "Google Workspace",
    icon: GoogleWorkspaceProviderBadge,
  },
  iac: {
    label: "Infrastructure as Code",
    icon: IacProviderBadge,
  },
  image: {
    label: "Container Registry",
    icon: ImageProviderBadge,
  },
  oraclecloud: {
    label: "Oracle Cloud Infrastructure",
    icon: OracleCloudProviderBadge,
  },
  mongodbatlas: {
    label: "MongoDB Atlas",
    icon: MongoDBAtlasProviderBadge,
  },
  alibabacloud: {
    label: "Alibaba Cloud",
    icon: AlibabaCloudProviderBadge,
  },
  cloudflare: {
    label: "Cloudflare",
    icon: CloudflareProviderBadge,
  },
  openstack: {
    label: "OpenStack",
    icon: OpenStackProviderBadge,
  },
};

/** Common props shared by both batch and instant modes. */
interface ProviderTypeSelectorBaseProps {
  providers: ProviderProps[];
}

/** Batch mode: caller controls both pending state and notification callback (all-or-nothing). */
interface ProviderTypeSelectorBatchProps extends ProviderTypeSelectorBaseProps {
  /**
   * Called instead of navigating immediately.
   * Use this on pages that batch filter changes (e.g. Findings).
   *
   * @param filterKey - The raw filter key without "filter[]" wrapper, e.g. "provider_type__in"
   * @param values - The selected values array
   */
  onBatchChange: (filterKey: string, values: string[]) => void;
  /**
   * Pending selected values controlled by the parent.
   * Reflects pending state before Apply is clicked.
   */
  selectedValues: string[];
}

/** Instant mode: URL-driven — neither callback nor controlled value. */
interface ProviderTypeSelectorInstantProps
  extends ProviderTypeSelectorBaseProps {
  onBatchChange?: never;
  selectedValues?: never;
}

type ProviderTypeSelectorProps =
  | ProviderTypeSelectorBatchProps
  | ProviderTypeSelectorInstantProps;

export const ProviderTypeSelector = ({
  providers,
  onBatchChange,
  selectedValues,
}: ProviderTypeSelectorProps) => {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  const currentProviders = searchParams.get("filter[provider_type__in]") || "";
  const urlSelectedTypes = currentProviders
    ? currentProviders.split(",").filter(Boolean)
    : [];

  // In batch mode, use the parent-controlled pending values; otherwise, use URL state.
  const selectedTypes = onBatchChange ? selectedValues : urlSelectedTypes;

  const handleMultiValueChange = (values: string[]) => {
    if (onBatchChange) {
      onBatchChange("provider_type__in", values);
      return;
    }
    navigateWithParams((params) => {
      // Update provider_type__in
      if (values.length > 0) {
        params.set("filter[provider_type__in]", values.join(","));
      } else {
        params.delete("filter[provider_type__in]");
      }
    });
  };

  const availableTypes = Array.from(
    new Set(
      providers
        // .filter((p) => p.attributes.connection?.connected)
        .map((p) => p.attributes.provider),
    ),
  ).filter((type): type is ProviderType => type in PROVIDER_DATA);

  const renderIcon = (providerType: ProviderType) => {
    const IconComponent = PROVIDER_DATA[providerType].icon;
    return (
      <Suspense fallback={<IconPlaceholder width={24} height={24} />}>
        <IconComponent width={24} height={24} />
      </Suspense>
    );
  };

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null;
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0] as ProviderType;
      return (
        <span className="flex min-w-0 items-center gap-2">
          {renderIcon(providerType)}
          <span className="truncate">{PROVIDER_DATA[providerType].label}</span>
        </span>
      );
    }
    return (
      <span className="min-w-0 truncate">
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
      <MultiSelect
        values={selectedTypes}
        onValuesChange={handleMultiValueChange}
      >
        <MultiSelectTrigger
          id="provider-type-selector"
          aria-labelledby="provider-type-label"
        >
          {selectedLabel() || <MultiSelectValue placeholder="All providers" />}
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          {availableTypes.length > 0 ? (
            <>
              <div
                role="option"
                aria-selected={selectedTypes.length === 0}
                aria-label="Select all providers (clears current selection to show all)"
                tabIndex={0}
                className="text-text-neutral-secondary flex w-full cursor-pointer items-center gap-3 rounded-lg px-4 py-3 text-sm font-semibold hover:bg-slate-200 dark:hover:bg-slate-700/50"
                onClick={() => handleMultiValueChange([])}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    handleMultiValueChange([]);
                  }
                }}
              >
                Select All
              </div>
              {availableTypes.map((providerType) => (
                <MultiSelectItem
                  key={providerType}
                  value={providerType}
                  badgeLabel={PROVIDER_DATA[providerType].label}
                  aria-label={`${PROVIDER_DATA[providerType].label} provider`}
                >
                  <span aria-hidden="true">{renderIcon(providerType)}</span>
                  <span>{PROVIDER_DATA[providerType].label}</span>
                </MultiSelectItem>
              ))}
            </>
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              No connected providers available
            </div>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};
