"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";

import {
  ProviderTypeIcon,
  ProviderTypeIconStack,
} from "@/components/icons/providers-badge/provider-type-icon";
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

/** Common props shared by both batch and instant modes. */
interface AccountsSelectorBaseProps {
  providers: ProviderProps[];
  search?: MultiSelectSearchProp;
  filterKey?: AccountSelectorFilter;
  id?: string;
  disabledValues?: string[];
  closeOnSelect?: boolean;
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
  closeOnSelect = false,
}: AccountsSelectorProps) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();
  const [selectorOpen, setSelectorOpen] = useState(false);

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
      if (closeOnSelect) setSelectorOpen(false);
      return;
    }
    navigateWithParams((params) => {
      params.delete(urlFilterKey);

      if (enabledIds.length > 0) {
        params.set(urlFilterKey, enabledIds.join(","));
      }
    });
    if (closeOnSelect) setSelectorOpen(false);
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null;
    if (selectedIds.length === 1) {
      const p = providers.find((pr) => getProviderValue(pr) === selectedIds[0]);
      const name = p ? p.attributes.alias || p.attributes.uid : selectedIds[0];
      return (
        <span className="flex min-w-0 items-center gap-2">
          {p && <ProviderTypeIcon type={p.attributes.provider} />}
          <span className="truncate">{name}</span>
        </span>
      );
    }
    // One icon per selected account (no dedupe): two accounts of the same
    // provider show two icons, disambiguated by the UID tooltip on hover.
    const items = selectedIds
      .map((selectedId) =>
        providers.find((pr) => getProviderValue(pr) === selectedId),
      )
      .filter((p): p is ProviderProps => Boolean(p))
      .map((p) => ({
        key: p.id,
        type: p.attributes.provider as ProviderType,
        tooltip: p.attributes.uid,
      }));
    return (
      <span className="flex min-w-0 items-center gap-2">
        <ProviderTypeIconStack items={items} />
        <span className="truncate">
          {selectedIds.length} Providers selected
        </span>
      </span>
    );
  };

  return (
    <div className="relative">
      <label htmlFor={id} className="sr-only" id={labelId}>
        Filter by Provider. Select one or more Providers to filter results.
      </label>
      <MultiSelect
        values={selectedIds}
        onValuesChange={handleMultiValueChange}
        open={closeOnSelect ? selectorOpen : undefined}
        onOpenChange={closeOnSelect ? setSelectorOpen : undefined}
      >
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
                    onSelect={() => {
                      if (closeOnSelect) setSelectorOpen(false);
                    }}
                  >
                    <span aria-hidden="true">
                      <ProviderTypeIcon type={providerType} />
                    </span>
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
