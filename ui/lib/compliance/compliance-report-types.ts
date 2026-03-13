/**
 * Compliance Report Type Constants
 *
 * This file defines the available compliance report types and their metadata.
 * When adding new compliance PDF reports, add entries here to maintain consistency.
 */

/**
 * Available compliance report types
 * Add new report types here as they become available
 */
export const COMPLIANCE_REPORT_TYPES = {
  THREATSCORE: "threatscore",
  ENS: "ens",
  NIS2: "nis2",
  CSA_CCM: "csa",
  // Future report types can be added here:
  // CIS: "cis",
  // NIST: "nist",
} as const;

/**
 * Type-safe report type extracted from COMPLIANCE_REPORT_TYPES
 */
export type ComplianceReportType =
  (typeof COMPLIANCE_REPORT_TYPES)[keyof typeof COMPLIANCE_REPORT_TYPES];

/**
 * Display names for each report type (user-facing)
 */
export const COMPLIANCE_REPORT_DISPLAY_NAMES: Record<
  ComplianceReportType,
  string
> = {
  [COMPLIANCE_REPORT_TYPES.THREATSCORE]: "ThreatScore",
  [COMPLIANCE_REPORT_TYPES.ENS]: "ENS RD2022",
  [COMPLIANCE_REPORT_TYPES.NIS2]: "NIS2",
  [COMPLIANCE_REPORT_TYPES.CSA_CCM]: "CSA CCM",
  // Add display names for future report types here
};

/**
 * Default button labels for download buttons
 */
export const COMPLIANCE_REPORT_BUTTON_LABELS: Record<
  ComplianceReportType,
  string
> = {
  [COMPLIANCE_REPORT_TYPES.THREATSCORE]: "PDF ThreatScore Report",
  [COMPLIANCE_REPORT_TYPES.ENS]: "PDF ENS Report",
  [COMPLIANCE_REPORT_TYPES.NIS2]: "PDF NIS2 Report",
  [COMPLIANCE_REPORT_TYPES.CSA_CCM]: "PDF CSA CCM Report",
  // Add button labels for future report types here
};

/**
 * Maps compliance framework names (from API) to their report types
 * This mapping determines which frameworks support PDF reporting
 */
const FRAMEWORK_TO_REPORT_TYPE: Record<string, ComplianceReportType> = {
  ProwlerThreatScore: COMPLIANCE_REPORT_TYPES.THREATSCORE,
  ENS: COMPLIANCE_REPORT_TYPES.ENS,
  NIS2: COMPLIANCE_REPORT_TYPES.NIS2,
  "CSA-CCM": COMPLIANCE_REPORT_TYPES.CSA_CCM,
  // Add new framework mappings here as PDF support is added:
  // "CIS-1.5": COMPLIANCE_REPORT_TYPES.CIS,
  // "NIST-800-53": COMPLIANCE_REPORT_TYPES.NIST,
};

/**
 * Helper function to get report type from framework name
 * Returns undefined if framework doesn't support PDF reporting
 */
export const getReportTypeForFramework = (
  framework: string | undefined,
): ComplianceReportType | undefined => {
  if (!framework) return undefined;
  return FRAMEWORK_TO_REPORT_TYPE[framework];
};
