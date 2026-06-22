import type { SearchParamsProps } from "@/types/components";

/**
 * Provider-scope filter keys the compliance UI sets. A subset of the API's
 * `PROVIDER_FILTER_KEYS`; the backend (`ComplianceOverviewViewSet`) treats these
 * as an alternative to `filter[scan_id]` (XOR) and aggregates compliance across
 * the latest completed scan of each matching provider.
 */
export const COMPLIANCE_PROVIDER_FILTER_KEYS = [
  "filter[provider_type__in]",
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
] as const;

type SearchParamsLike = SearchParamsProps | URLSearchParams;

const readParam = (params: SearchParamsLike, key: string): string => {
  if (params instanceof URLSearchParams) {
    return params.get(key) ?? "";
  }
  const value = params[key];
  if (Array.isArray(value)) return value.join(",");
  return value ?? "";
};

/** True when any compliance provider-scope filter is present and non-empty. */
export const hasComplianceProviderFilters = (
  params: SearchParamsLike,
): boolean =>
  COMPLIANCE_PROVIDER_FILTER_KEYS.some(
    (key) => readParam(params, key).trim().length > 0,
  );

/** Returns only the present, non-empty provider-scope filters (CSV-joined). */
export const extractComplianceProviderFilters = (
  params: SearchParamsLike,
): Record<string, string> => {
  const result: Record<string, string> = {};
  for (const key of COMPLIANCE_PROVIDER_FILTER_KEYS) {
    const value = readParam(params, key).trim();
    if (value.length > 0) {
      result[key] = value;
    }
  }
  return result;
};
