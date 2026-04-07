"use client";

import { useSearchParams } from "next/navigation";
import { ReactNode } from "react";

import {
  AlibabaCloudProviderBadge,
  AWSProviderBadge,
  AzureProviderBadge,
  CloudflareProviderBadge,
  GCPProviderBadge,
  GitHubProviderBadge,
  GoogleWorkspaceProviderBadge,
  IacProviderBadge,
  ImageProviderBadge,
  KS8ProviderBadge,
  M365ProviderBadge,
  MongoDBAtlasProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
  VercelProviderBadge,
} from "@/components/icons/providers-badge";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import {
  getProviderDisplayName,
  type ProviderProps,
  type ProviderType,
} from "@/types/providers";

const PROVIDER_ICON: Record<ProviderType, ReactNode> = {
  aws: <AWSProviderBadge width={18} height={18} />,
  azure: <AzureProviderBadge width={18} height={18} />,
  gcp: <GCPProviderBadge width={18} height={18} />,
  kubernetes: <KS8ProviderBadge width={18} height={18} />,
  m365: <M365ProviderBadge width={18} height={18} />,
  github: <GitHubProviderBadge width={18} height={18} />,
  googleworkspace: <GoogleWorkspaceProviderBadge width={18} height={18} />,
  iac: <IacProviderBadge width={18} height={18} />,
  image: <ImageProviderBadge width={18} height={18} />,
  oraclecloud: <OracleCloudProviderBadge width={18} height={18} />,
  mongodbatlas: <MongoDBAtlasProviderBadge width={18} height={18} />,
  alibabacloud: <AlibabaCloudProviderBadge width={18} height={18} />,
  cloudflare: <CloudflareProviderBadge width={18} height={18} />,
  openstack: <OpenStackProviderBadge width={18} height={18} />,
  vercel: <VercelProviderBadge width={18} height={18} />,
};

/** Common props shared by both batch and instant modes. */
interface AccountsSelectorBaseProps {
  providers: ProviderProps[];
  /**
   * Currently selected provider types (from the pending ProviderTypeSelector state).
   * Used only for contextual description/empty-state messaging — does NOT narrow
   * the list of available accounts, which remains independent of provider selection.
   */
  selectedProviderTypes?: string[];
}

/** Batch mode: caller controls both pending state and notification callback (all-or-nothing). */
interface AccountsSelectorBatchProps extends AccountsSelectorBaseProps {
  /**
   * Called instead of navigating immediately.
   * Use this on pages that batch filter changes (e.g. Findings).
   *
   * @param filterKey - The raw filter key without "filter[]" wrapper, e.g. "provider_id__in"
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
interface AccountsSelectorInstantProps extends AccountsSelectorBaseProps {
  onBatchChange?: never;
  selectedValues?: never;
}

type AccountsSelectorProps =
  | AccountsSelectorBatchProps
  | AccountsSelectorInstantProps;

export function AccountsSelector({
  providers,
  onBatchChange,
  selectedValues,
  selectedProviderTypes,
}: AccountsSelectorProps) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  const filterKey = "filter[provider_id__in]";
  const current = searchParams.get(filterKey) || "";
  const urlSelectedIds = current ? current.split(",").filter(Boolean) : [];

  // In batch mode, use the parent-controlled pending values; otherwise, use URL state.
  const selectedIds = onBatchChange ? selectedValues : urlSelectedIds;
  const visibleProviders = providers;
  // .filter((p) => p.attributes.connection?.connected)

  const handleMultiValueChange = (ids: string[]) => {
    if (onBatchChange) {
      onBatchChange("provider_id__in", ids);
      return;
    }
    navigateWithParams((params) => {
      params.delete(filterKey);

      if (ids.length > 0) {
        params.set(filterKey, ids.join(","));
      }
    });
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null;
    if (selectedIds.length === 1) {
      const p = providers.find((pr) => pr.id === selectedIds[0]);
      const name = p ? p.attributes.alias || p.attributes.uid : selectedIds[0];
      return <span className="truncate">{name}</span>;
    }
    return (
      <span className="truncate">{selectedIds.length} accounts selected</span>
    );
  };

  // Build a contextual description based on currently selected provider types.
  // This is purely for user guidance (aria label + empty state) and does NOT
  // narrow the list of available accounts — all providers remain selectable.
  const filterDescription =
    selectedProviderTypes && selectedProviderTypes.length > 0
      ? `Accounts for ${selectedProviderTypes.map(getProviderDisplayName).join(", ")}`
      : "All connected cloud provider accounts";

  return (
    <div className="relative">
      <label
        htmlFor="accounts-selector"
        className="sr-only"
        id="accounts-label"
      >
        Filter by cloud provider account. {filterDescription}. Select one or
        more accounts to view findings.
      </label>
      <MultiSelect values={selectedIds} onValuesChange={handleMultiValueChange}>
        <MultiSelectTrigger
          id="accounts-selector"
          aria-labelledby="accounts-label"
        >
          {selectedLabel() || <MultiSelectValue placeholder="All accounts" />}
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          {visibleProviders.length > 0 ? (
            <>
              <div
                role="option"
                aria-selected={selectedIds.length === 0}
                aria-label="Select all accounts (clears current selection to show all)"
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
              {visibleProviders.map((p) => {
                const id = p.id;
                const displayName = p.attributes.alias || p.attributes.uid;
                const providerType = p.attributes.provider as ProviderType;
                const icon = PROVIDER_ICON[providerType];
                return (
                  <MultiSelectItem
                    key={id}
                    value={id}
                    badgeLabel={displayName}
                    aria-label={`${displayName} account (${providerType.toUpperCase()})`}
                  >
                    <span aria-hidden="true">{icon}</span>
                    <span className="truncate">{displayName}</span>
                  </MultiSelectItem>
                );
              })}
            </>
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              {selectedProviderTypes && selectedProviderTypes.length > 0
                ? `No accounts available for ${selectedProviderTypes.map(getProviderDisplayName).join(", ")}`
                : "No connected accounts available"}
            </div>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
}
