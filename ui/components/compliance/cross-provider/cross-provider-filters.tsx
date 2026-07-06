"use client";

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

interface CrossProviderFiltersProps {
  /** Every provider account of a type compatible with the current
   *  framework — already narrowed by the caller to ``compatible_providers``.
   *  Not filtered by connection status: disconnected accounts still show up
   *  so the user can see (and filter to) them, same as the account
   *  selectors elsewhere in the app. */
  providers: ProviderProps[];
  /** Every provider group in the tenant — not narrowed by framework
   *  compatibility, same as every other provider-group filter in the app
   *  (a group can span multiple provider types). */
  providerGroups: ProviderGroup[];
}

const FILTER_CONTROL_CLASS =
  "w-full sm:max-w-[240px] sm:min-w-[180px] sm:flex-1";

/**
 * Provider type / account / group narrowing for the cross-provider
 * compliance detail page. Instant mode: picking a value pushes
 * ``filter[provider_type__in]`` / ``filter[provider_id__in]`` /
 * ``filter[provider_groups__in]`` straight into the URL, which the server
 * component re-reads on navigation and re-runs the aggregation against just
 * the selected providers (unlike the search/status controls in
 * ``CrossProviderExplorerCard``, which only filter the already-fetched
 * payload client-side).
 */
export const CrossProviderFilters = ({
  providers,
  providerGroups,
}: CrossProviderFiltersProps) => {
  if (providers.length === 0) return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      <ProviderAccountSelectors
        providers={providers}
        providerSelectorClassName={FILTER_CONTROL_CLASS}
        accountSelectorClassName={FILTER_CONTROL_CLASS}
      />
      <div className={FILTER_CONTROL_CLASS}>
        <ProviderGroupSelector groups={providerGroups} />
      </div>
      <ClearFiltersButton showCount />
    </div>
  );
};
