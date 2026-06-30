const COMPLIANCE_PAGE_TAB = {
  PER_SCAN: "per-scan",
  CROSS_PROVIDER: "cross-provider",
} as const;

type CompliancePageTab =
  (typeof COMPLIANCE_PAGE_TAB)[keyof typeof COMPLIANCE_PAGE_TAB];

function isCompliancePageTab(value: string): value is CompliancePageTab {
  return Object.values(COMPLIANCE_PAGE_TAB).includes(
    value as CompliancePageTab,
  );
}

function getCompliancePageTab(
  value: string | string[] | undefined,
): CompliancePageTab {
  if (typeof value !== "string") {
    return COMPLIANCE_PAGE_TAB.PER_SCAN;
  }
  return isCompliancePageTab(value) ? value : COMPLIANCE_PAGE_TAB.PER_SCAN;
}

export type { CompliancePageTab };
export { COMPLIANCE_PAGE_TAB, getCompliancePageTab };
