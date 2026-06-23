import type { SearchParamsProps } from "@/types/components";
import { FILTER_FIELD, FilterParam } from "@/types/filters";

/**
 * Provider-scope filter param keys the compliance UI sets — the same three the
 * overview dashboard uses, derived from the shared `FILTER_FIELD` source of
 * truth. The backend (`ComplianceOverviewViewSet`) treats these as an
 * alternative to `filter[scan_id]` (XOR) and aggregates compliance across the
 * latest completed scan of each matching provider.
 */
export type ComplianceProviderFilterParam = FilterParam<
  (typeof FILTER_FIELD)["PROVIDER_TYPE" | "PROVIDER_ID" | "PROVIDER_GROUPS"]
>;

/** Present, CSV-joined provider-scope filters (aggregated mode). */
export type ComplianceProviderFilters = Partial<
  Record<ComplianceProviderFilterParam, string>
>;

/**
 * Filters the compliance server actions accept: the provider-scope keys above
 * (aggregated mode) or `filter[scan_id]` (single-scan mode) — XOR.
 */
export type ComplianceFilters = Partial<
  Record<ComplianceProviderFilterParam | FilterParam<"scan_id">, string>
>;

export const COMPLIANCE_PROVIDER_FILTER_KEYS = [
  `filter[${FILTER_FIELD.PROVIDER_TYPE}]`,
  `filter[${FILTER_FIELD.PROVIDER_ID}]`,
  `filter[${FILTER_FIELD.PROVIDER_GROUPS}]`,
] as const satisfies ReadonlyArray<ComplianceProviderFilterParam>;

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
): ComplianceProviderFilters => {
  const result: ComplianceProviderFilters = {};
  for (const key of COMPLIANCE_PROVIDER_FILTER_KEYS) {
    const value = readParam(params, key).trim();
    if (value.length > 0) {
      result[key] = value;
    }
  }
  return result;
};
