"use client";

import { useSearchParams } from "next/navigation";

import {
  PROVIDER_TYPE_DATA,
  ProviderTypeIcon,
  ProviderTypeIconStack,
} from "@/components/icons/providers-badge/provider-type-icon";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  type MultiSelectSearchProp,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { type ProviderProps, ProviderType } from "@/types/providers";

/** Common props shared by both batch and instant modes. */
interface ProviderTypeSelectorBaseProps {
  providers: ProviderProps[];
  search?: MultiSelectSearchProp;
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
  search = {
    placeholder: "Search Provider Types...",
    emptyMessage: "No Provider Types found.",
  },
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
  )
    .filter((type): type is ProviderType => type in PROVIDER_TYPE_DATA)
    .sort((a, b) =>
      PROVIDER_TYPE_DATA[a].label.localeCompare(PROVIDER_TYPE_DATA[b].label),
    );

  const selectedLabel = () => {
    if (selectedTypes.length === 0) return null;
    if (selectedTypes.length === 1) {
      const providerType = selectedTypes[0] as ProviderType;
      return (
        <span className="flex min-w-0 items-center gap-2">
          <span aria-hidden="true">
            <ProviderTypeIcon type={providerType} />
          </span>
          <span className="truncate">
            {PROVIDER_TYPE_DATA[providerType].label}
          </span>
        </span>
      );
    }
    return (
      <span className="flex min-w-0 items-center gap-2">
        <ProviderTypeIconStack
          items={(selectedTypes as ProviderType[]).map((type) => ({
            key: type,
            type,
            tooltip: PROVIDER_TYPE_DATA[type].label,
          }))}
        />
        <span className="min-w-0 truncate">
          {selectedTypes.length} Provider Types selected
        </span>
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
        Filter by Provider Type. Select one or more Provider Types to view
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
          {selectedLabel() || (
            <MultiSelectValue placeholder="All Provider Types" />
          )}
        </MultiSelectTrigger>
        <MultiSelectContent search={search}>
          {availableTypes.length > 0 ? (
            <>
              <div
                role="option"
                aria-selected={selectedTypes.length === 0}
                aria-disabled={selectedTypes.length === 0}
                aria-label="Select all Provider Types (clears current selection to show all)"
                tabIndex={0}
                className="text-text-neutral-secondary flex w-full cursor-pointer items-center gap-3 rounded-lg px-4 py-3 text-sm font-semibold hover:bg-slate-200 aria-disabled:cursor-not-allowed aria-disabled:opacity-50 dark:hover:bg-slate-700/50"
                onClick={() => {
                  if (selectedTypes.length === 0) return;
                  handleMultiValueChange([]);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    if (selectedTypes.length === 0) return;
                    handleMultiValueChange([]);
                  }
                }}
              >
                {selectedTypes.length === 0 ? "All selected" : "Select All"}
              </div>
              {availableTypes.map((providerType) => (
                <MultiSelectItem
                  key={providerType}
                  value={providerType}
                  badgeLabel={PROVIDER_TYPE_DATA[providerType].label}
                  keywords={[
                    providerType,
                    PROVIDER_TYPE_DATA[providerType].label,
                  ]}
                  aria-label={`${PROVIDER_TYPE_DATA[providerType].label} Provider Type`}
                >
                  <span aria-hidden="true">
                    <ProviderTypeIcon type={providerType} size={24} />
                  </span>
                  <span>{PROVIDER_TYPE_DATA[providerType].label}</span>
                </MultiSelectItem>
              ))}
            </>
          ) : (
            <div className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">
              No connected Provider Types available
            </div>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
};
