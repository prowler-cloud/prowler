import { COMPLIANCE_TAB, type ComplianceTab } from "../_types";

function isComplianceTab(value: string): value is ComplianceTab {
  return Object.values(COMPLIANCE_TAB).includes(value as ComplianceTab);
}

/** Resolves `?tab=` into a valid tab, defaulting to Per Scan so existing
 *  bookmarks (no query param) keep working. */
function getComplianceTab(value: string | string[] | undefined): ComplianceTab {
  if (typeof value !== "string") {
    return COMPLIANCE_TAB.PER_SCAN;
  }

  return isComplianceTab(value) ? value : COMPLIANCE_TAB.PER_SCAN;
}

export { getComplianceTab };
