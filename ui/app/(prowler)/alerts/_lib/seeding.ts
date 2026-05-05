import type { AlertsFilterBag } from "../_types";

const PORTABLE_FINDINGS_FILTER_KEYS = [
  "severity",
  "severity.in",
  "severity__in",
  "delta",
  "delta.in",
  "delta__in",
  "check_id",
  "check_id.in",
  "check_id__in",
  "finding_group_id",
  "finding_group_id.in",
  "finding_group_id__in",
  "categories",
  "categories.in",
  "categories__in",
  "category",
  "category__in",
  "resource_regions",
  "resource_regions.in",
  "resource_regions__in",
  "region",
  "region__in",
  "resource_services",
  "resource_services.in",
  "resource_services__in",
  "service",
  "service__in",
  "resource_types",
  "resource_types.in",
  "resource_types__in",
  "resource_type",
  "resource_type__in",
  "resource_groups",
  "resource_groups.in",
  "resource_groups__in",
  "resource_uid",
  "resource_uid.in",
  "resource_uid__in",
  "provider_id",
  "provider_id.in",
  "provider_id__in",
  "provider_type",
  "provider_type.in",
  "provider_type__in",
] as const;

const PORTABLE_FINDINGS_FILTER_KEY_SET = new Set<string>(
  PORTABLE_FINDINGS_FILTER_KEYS,
);

const NON_FILTER_QUERY_KEYS = new Set(["sort", "page", "pageSize"]);

const unwrapFilterKey = (rawKey: string): string => {
  if (rawKey.startsWith("filter[") && rawKey.endsWith("]")) {
    return rawKey.slice("filter[".length, -1);
  }

  return rawKey;
};

const isFilterKey = (rawKey: string): boolean =>
  rawKey.startsWith("filter[") && rawKey.endsWith("]");

const hasSeedableFilterValue = (value: AlertsFilterBag[string]): boolean => {
  const values = Array.isArray(value) ? value : [value];

  return values.some((entry) =>
    entry
      .split(",")
      .map((part) => part.trim())
      .some(Boolean),
  );
};

/**
 * Product invariant for the Findings entry point: any visible filter can open
 * the alert modal, but only backend-portable filters are sent as rule criteria.
 */
export const canSeedAlertFromFindingsFilters = (
  filterBag: AlertsFilterBag,
): boolean =>
  Object.entries(filterBag).some(([rawKey, value]) => {
    if (!isFilterKey(rawKey) || NON_FILTER_QUERY_KEYS.has(rawKey)) return false;

    return hasSeedableFilterValue(value);
  });

export const toPortableAlertFilterBag = (
  filterBag: AlertsFilterBag,
): AlertsFilterBag =>
  Object.fromEntries(
    Object.entries(filterBag).filter(([rawKey, value]) => {
      const key = unwrapFilterKey(rawKey);
      return (
        PORTABLE_FINDINGS_FILTER_KEY_SET.has(key) &&
        hasSeedableFilterValue(value)
      );
    }),
  );
