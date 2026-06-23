import type { ComplianceProviderFilters } from "./compliance-provider-filters";

interface ComplianceDetailPathParams {
  /** Framework title as shown on the card (URL-encoded into the path). */
  title: string;
  complianceId: string;
  version: string;
  /** Single-scan scope. Omitted when provider filters drive aggregated mode. */
  scanId?: string | null;
  regionFilter?: string | null;
  /**
   * Aggregated-mode scope: provider-filter keys (e.g. filter[provider_type__in])
   * carried instead of scanId. XOR with scanId — when present, scanId is dropped.
   */
  providerFilters?: ComplianceProviderFilters;
}

/** Builds the `/compliance/[compliancetitle]` detail URL used by the overview cards. */
export function buildComplianceDetailPath({
  title,
  complianceId,
  version,
  scanId,
  regionFilter,
  providerFilters,
}: ComplianceDetailPathParams): string {
  const params = new URLSearchParams();
  params.set("complianceId", complianceId);
  params.set("version", version);

  const providerEntries = providerFilters
    ? Object.entries(providerFilters).filter(
        (entry): entry is [string, string] => Boolean(entry[1]),
      )
    : [];
  if (providerEntries.length > 0) {
    for (const [key, value] of providerEntries) {
      params.set(key, value);
    }
  } else if (scanId) {
    params.set("scanId", scanId);
  }

  if (regionFilter) {
    params.set("filter[region__in]", regionFilter);
  }
  return `/compliance/${encodeURIComponent(title)}?${params.toString()}`;
}
