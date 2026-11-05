import { COMPLIANCE_TAB, type ComplianceTab } from "@/types/compliance";

function isComplianceTab(value: string): value is ComplianceTab {
  return Object.values(COMPLIANCE_TAB).includes(value as ComplianceTab);
}

/** Resolves `?tab=` into a valid tab, defaulting to Cross Provider — the
 *  Multiple Scans tab, which owns the bare `/compliance` route.
 *
 *  A `scanId` with no explicit tab means the link predates the tab split (or
 *  was shared from Single Scan), so it keeps resolving to Per Scan instead of
 *  landing on the aggregated view, which ignores the scan entirely. */
function getComplianceTab(
  value: string | string[] | undefined,
  scanId?: string | string[] | undefined,
): ComplianceTab {
  if (typeof value === "string" && isComplianceTab(value)) {
    return value;
  }

  return typeof scanId === "string" && scanId
    ? COMPLIANCE_TAB.PER_SCAN
    : COMPLIANCE_TAB.CROSS_PROVIDER;
}

export { getComplianceTab };
