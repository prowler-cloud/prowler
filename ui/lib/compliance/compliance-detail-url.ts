interface ComplianceDetailPathParams {
  /** Framework title as shown on the card (URL-encoded into the path). */
  title: string;
  complianceId: string;
  version: string;
  scanId: string;
  regionFilter?: string | null;
}

/** Builds the `/compliance/[compliancetitle]` detail URL used by the overview cards. */
export function buildComplianceDetailPath({
  title,
  complianceId,
  version,
  scanId,
  regionFilter,
}: ComplianceDetailPathParams): string {
  const params = new URLSearchParams();
  params.set("complianceId", complianceId);
  params.set("version", version);
  params.set("scanId", scanId);
  if (regionFilter) {
    params.set("filter[region__in]", regionFilter);
  }
  return `/compliance/${encodeURIComponent(title)}?${params.toString()}`;
}
