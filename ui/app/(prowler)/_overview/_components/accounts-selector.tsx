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
  OktaProviderBadge,
  OpenStackProviderBadge,
  OracleCloudProviderBadge,
  VercelProviderBadge,
} from "@/components/icons/providers-badge";
import { Badge } from "@/components/shadcn";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  type MultiSelectSearchProp,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import {
  getProviderDisplayName,
  type ProviderProps,
  type ProviderType,
} from "@/types/providers";

const ACCOUNT_SELECTOR_FILTER = {
  PROVIDER_ID: "provider_id__in",
  PROVIDER_UID: "provider_uid__in",
} as const;

type AccountSelectorFilter =
  (typeof ACCOUNT_SELECTOR_FILTER)[keyof typeof ACCOUNT_SELECTOR_FILTER];

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
  okta: <OktaProviderBadge width={18} height={18} />,
};

/** Common props shared by both batch and instant modes. */
interface AccountsSelectorBaseProps {
  providers: ProviderProps[];
  search?: MultiSelectSearchProp;
  filterKey?: AccountSelectorFilter;
  id?: string;
  disabledValues?: string[];
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
  filterKey = ACCOUNT_SELECTOR_FILTER.PROVIDER_ID,
  id = "accounts-selector",
  disabledValues = [],
  search = {
    placeholder: "Search Providers...",
    emptyMessage: "No Providers found.",
  },
}: AccountsSelectorProps) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  const labelId = `${id}-label`;
  const urlFilterKey = `filter[${filterKey}]`;
  const current = searchParams.get(urlFilterKey) || "";
  const urlSelectedIds = current ? current.split(",").filter(Boolean) : [];

  const visibleProviders = providers;
  const getProviderValue = (provider: ProviderProps) =>
    filterKey === ACCOUNT_SELECTOR_FILTER.PROVIDER_UID
      ? provider.attributes.uid
      : provider.id;
  const disabledValuesSet = new Set(disabledValues);

  // In batch mode, use the parent-controlled pending values; otherwise, use URL state.
  const selectedIds = (onBatchChange ? selectedValues : urlSelectedIds).filter(
    (id) => !disabledValuesSet.has(id),
  );

  const handleMultiValueChange = (ids: string[]) => {
    const enabledIds = ids.filter((id) => !disabledValuesSet.has(id));

    if (onBatchChange) {
      onBatchChange(filterKey, enabledIds);
      return;
    }
    navigateWithParams((params) => {
      params.delete(urlFilterKey);

      if (enabledIds.length > 0) {
        params.set(urlFilterKey, enabledIds.join(","));
      }
    });
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null;
    if (selectedIds.length === 1) {
      const p = providers.find((pr) => getProviderValue(pr) === selectedIds[0]);
      const name = p ? p.attributes.alias || p.attributes.uid : selectedIds[0];
      return <span className="truncate">{name}</span>;
    }
    return (
      <span className="truncate">{selectedIds.length} Providers selected</span>
    );
  };

  return (
    <div className="relative">
      <label htmlFor={id} className="sr-only" id={labelId}>
        Filter by Provider. Select one or more Providers to filter results.
      </label>
      <MultiSelect values={selectedIds} onValuesChange={handleMultiValueChange}>
        <MultiSelectTrigger id={id} aria-labelledby={labelId}>
          {selectedLabel() || <MultiSelectValue placeholder="All Providers" />}
        </MultiSelectTrigger>
        <MultiSelectContent search={search}>
          {visibleProviders.length > 0 ? (
            <>
              <div
                role="option"
                aria-selected={selectedIds.length === 0}
                aria-disabled={selectedIds.length === 0}
                aria-label="Select all Providers (clears current selection to show all)"
                tabIndex={0}
                className="text-text-neutral-secondary flex w-full cursor-pointer items-center gap-3 rounded-lg px-4 py-3 text-sm font-semibold hover:bg-slate-200 aria-disabled:cursor-not-allowed aria-disabled:opacity-50 dark:hover:bg-slate-700/50"
                onClick={() => {
                  if (selectedIds.length === 0) return;
                  handleMultiValueChange([]);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    if (selectedIds.length === 0) return;
                    handleMultiValueChange([]);
                  }
                }}
              >
                {selectedIds.length === 0 ? "All selected" : "Select All"}
              </div>
              {visibleProviders.map((p) => {
                const value = getProviderValue(p);
                const isDisabled = disabledValuesSet.has(value);
                const displayName = p.attributes.alias || p.attributes.uid;
                const providerType = p.attributes.provider as ProviderType;
                const icon = PROVIDER_ICON[providerType];
                const searchKeywords = [
                  displayName,
                  p.attributes.alias,
                  p.attributes.uid,
                  providerType,
                  getProviderDisplayName(providerType),
                ].filter(Boolean);
                return (
                  <MultiSelectItem
                    key={p.id}
                    value={value}
                    badgeLabel={displayName}
                    keywords={searchKeywords}
                    disabled={isDisabled}
                    aria-label={`${displayName} Provider (${providerType.toUpperCase()})`}
                  >
                    <span aria-hidden="true">{icon}</span>
                    <span className="flex min-w-0 flex-1 items-center gap-2">
                      <span className="truncate">{displayName}</span>
                      {isDisabled && <Badge variant="tag">Disconnected</Badge>}
                    </span>
                  </MultiSelectItem>
                );
              })}
            </>
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              No connected Providers available
            </div>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
}
