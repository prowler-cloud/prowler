import type {
  CrossAccountApiFilters,
  CrossAccountFrameworkEntry,
} from "../_types";

/** Cross-account filter params forwarded from the overview into detail
 *  links (and consumed back by the detail page). The provider type is fixed
 *  per view, so unlike cross-provider there is no provider_type__in here. */
const CROSS_ACCOUNT_FILTER_PARAMS = [
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
] as const;

/** Parses the URL filter params the cross-account endpoint accepts. Kept
 *  next to CROSS_ACCOUNT_FILTER_PARAMS so the overview section and the
 *  detail island build identical, typed filter objects. */
export const parseCrossAccountFilters = (
  searchParams: Record<string, string | string[] | undefined>,
): CrossAccountApiFilters => ({
  providerIds: searchParams["filter[provider_id__in]"]?.toString() || undefined,
  providerGroups:
    searchParams["filter[provider_groups__in]"]?.toString() || undefined,
});

export const buildCrossAccountDetailHref = (
  entry: Pick<
    CrossAccountFrameworkEntry,
    "complianceId" | "title" | "version" | "providerType"
  >,
  searchParams?: Record<string, string | string[] | undefined>,
): string => {
  const params = new URLSearchParams();
  params.set("mode", "cross-account");
  params.set("complianceId", entry.complianceId);
  params.set("version", entry.version);
  params.set("providerType", entry.providerType);

  for (const key of CROSS_ACCOUNT_FILTER_PARAMS) {
    const value = searchParams?.[key]?.toString();
    if (value) params.set(key, value);
  }

  return `/compliance/${encodeURIComponent(entry.title)}?${params.toString()}`;
};
