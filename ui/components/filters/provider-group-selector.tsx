"use client";

import { useSearchParams } from "next/navigation";

import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  type MultiSelectSearchProp,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useUrlFilters } from "@/hooks/use-url-filters";
import type { ProviderGroup } from "@/types/components";
import { FILTER_FIELD } from "@/types/filters";

const PROVIDER_GROUP_FILTER_KEY = FILTER_FIELD.PROVIDER_GROUPS;
const URL_FILTER_KEY = `filter[${PROVIDER_GROUP_FILTER_KEY}]`;

/** Common props shared by both batch and instant modes. */
interface ProviderGroupSelectorBaseProps {
  groups: ProviderGroup[];
  search?: MultiSelectSearchProp;
  /** DOM id for the control; pass a unique one when rendering more than one. */
  id?: string;
  /**
   * Instant mode only: extra URL params to delete when the selection changes
   * (e.g. ["page", "scanId"]), mirroring ProviderAccountSelectors. Ignored in
   * batch mode, where the parent owns URL updates.
   */
  paramsToDeleteOnChange?: string[];
}

/** Batch mode: caller controls both pending state and notification callback (all-or-nothing). */
interface ProviderGroupSelectorBatchProps
  extends ProviderGroupSelectorBaseProps {
  /**
   * Called instead of navigating immediately.
   * Use this on pages that batch filter changes (e.g. Findings).
   *
   * @param filterKey - The raw filter key without "filter[]" wrapper, e.g. "provider_groups__in"
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
interface ProviderGroupSelectorInstantProps
  extends ProviderGroupSelectorBaseProps {
  onBatchChange?: never;
  selectedValues?: never;
}

type ProviderGroupSelectorProps =
  | ProviderGroupSelectorBatchProps
  | ProviderGroupSelectorInstantProps;

export function ProviderGroupSelector({
  groups,
  onBatchChange,
  selectedValues,
  id = "provider-group-selector",
  search = {
    placeholder: "Search Provider Groups...",
    emptyMessage: "No Provider Groups found.",
  },
  paramsToDeleteOnChange = [],
}: ProviderGroupSelectorProps) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();
  const labelId = `${id}-label`;

  const current = searchParams.get(URL_FILTER_KEY) || "";
  const urlSelectedIds = current ? current.split(",").filter(Boolean) : [];

  // In batch mode, use the parent-controlled pending values; otherwise, use URL state.
  const selectedIds = onBatchChange ? selectedValues : urlSelectedIds;

  const handleMultiValueChange = (ids: string[]) => {
    if (onBatchChange) {
      onBatchChange(PROVIDER_GROUP_FILTER_KEY, ids);
      return;
    }
    navigateWithParams((params) => {
      if (ids.length > 0) {
        params.set(URL_FILTER_KEY, ids.join(","));
      } else {
        params.delete(URL_FILTER_KEY);
      }
      paramsToDeleteOnChange.forEach((key) => params.delete(key));
    });
  };

  const selectedLabel = () => {
    if (selectedIds.length === 0) return null;
    if (selectedIds.length === 1) {
      const group = groups.find((g) => g.id === selectedIds[0]);
      return (
        <span className="truncate">
          {group ? group.attributes.name : selectedIds[0]}
        </span>
      );
    }
    return (
      <span className="truncate">
        {selectedIds.length} Provider Groups selected
      </span>
    );
  };

  return (
    <div className="relative">
      <label htmlFor={id} className="sr-only" id={labelId}>
        Filter by Provider Group. Select one or more Provider Groups to filter
        results.
      </label>
      <MultiSelect values={selectedIds} onValuesChange={handleMultiValueChange}>
        <MultiSelectTrigger id={id} aria-labelledby={labelId}>
          {selectedLabel() || (
            <MultiSelectValue placeholder="All Provider Groups" />
          )}
        </MultiSelectTrigger>
        <MultiSelectContent search={search}>
          {/* No items when empty: the MultiSelect's own emptyMessage is the
              single empty state (avoids a duplicate "none" message). */}
          {groups.length > 0 && (
            <>
              <div
                role="option"
                aria-selected={selectedIds.length === 0}
                aria-disabled={selectedIds.length === 0}
                aria-label="Select all Provider Groups (clears current selection to show all)"
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
              {groups.map((group) => (
                <MultiSelectItem
                  key={group.id}
                  value={group.id}
                  badgeLabel={group.attributes.name}
                  keywords={[group.attributes.name]}
                  aria-label={`${group.attributes.name} Provider Group`}
                >
                  <span className="truncate">{group.attributes.name}</span>
                </MultiSelectItem>
              ))}
            </>
          )}
        </MultiSelectContent>
      </MultiSelect>
    </div>
  );
}
