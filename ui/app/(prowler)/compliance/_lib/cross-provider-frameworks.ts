import type { CrossProviderApiFilters } from "../_types";

// One universal framework card. Built from the API catalog, never hardcoded:
// see `./cross-provider-catalog`.
export interface CrossProviderFrameworkEntry {
  complianceId: string;
  /** Also the [compliancetitle] segment and the icon lookup key. */
  title: string;
  version: string;
  description: string;
  /** Raw from the catalog — narrow with `isKnownProviderType` only where an
   *  icon or label is needed. */
  providerTypes: string[];
}

const CROSS_PROVIDER_FILTER_PARAMS = [
  "filter[provider_type__in]",
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
] as const;

export const parseCrossProviderFilters = (
  searchParams: Record<string, string | string[] | undefined>,
): CrossProviderApiFilters => ({
  providerTypes:
    searchParams["filter[provider_type__in]"]?.toString() || undefined,
  providerIds: searchParams["filter[provider_id__in]"]?.toString() || undefined,
  providerGroups:
    searchParams["filter[provider_groups__in]"]?.toString() || undefined,
});

export const buildCrossProviderDetailHref = (
  entry: Pick<
    CrossProviderFrameworkEntry,
    "complianceId" | "title" | "version"
  >,
  searchParams?: Record<string, string | string[] | undefined>,
): string => {
  const params = new URLSearchParams();
  params.set("mode", "cross-provider");
  params.set("complianceId", entry.complianceId);
  params.set("version", entry.version);

  for (const key of CROSS_PROVIDER_FILTER_PARAMS) {
    const value = searchParams?.[key]?.toString();
    if (value) params.set(key, value);
  }

  return `/compliance/${encodeURIComponent(entry.title)}?${params.toString()}`;
};
