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
  CIS: "cis",
  // Future report types can be added here:
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
  [COMPLIANCE_REPORT_TYPES.CIS]: "CIS Benchmark",
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
  [COMPLIANCE_REPORT_TYPES.CIS]: "PDF CIS Benchmark Report",
  // Add button labels for future report types here
};

/**
 * Maps compliance framework names (from API) to their report types
 * This mapping determines which frameworks support PDF reporting.
 *
 * NOTE: CIS is intentionally NOT listed here. CIS has multiple variants per
 * provider (e.g. cis_1.4_aws, cis_5.0_aws, cis_6.0_aws) — see
 * `getReportTypeForComplianceId` below which resolves the CIS report type
 * from the unique compliance_id instead of a shared framework name.
 */
const FRAMEWORK_TO_REPORT_TYPE: Record<string, ComplianceReportType> = {
  ProwlerThreatScore: COMPLIANCE_REPORT_TYPES.THREATSCORE,
  ENS: COMPLIANCE_REPORT_TYPES.ENS,
  NIS2: COMPLIANCE_REPORT_TYPES.NIS2,
  "CSA-CCM": COMPLIANCE_REPORT_TYPES.CSA_CCM,
  // Add new framework mappings here as PDF support is added:
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

/**
 * Helper function to get report type from a specific compliance_id.
 *
 * Used for frameworks that ship multiple variants and cannot be identified
 * by a single framework name (currently: CIS). For every
 * compliance_id that starts with `cis_` (e.g. `cis_5.0_aws`) this returns
 * the CIS report type so the PDF download button is rendered.
 *
 * Returns undefined if the compliance_id does not match any per-variant
 * report type. Non-variant frameworks (ENS, NIS2, etc.) should keep relying
 * on `getReportTypeForFramework` instead.
 */
export const getReportTypeForComplianceId = (
  complianceId: string | undefined,
): ComplianceReportType | undefined => {
  if (!complianceId) return undefined;
  if (complianceId.startsWith("cis_")) {
    return COMPLIANCE_REPORT_TYPES.CIS;
  }
  return undefined;
};

/**
 * Matches CIS compliance_ids like `cis_5.0_aws`, `cis_1.10_kubernetes`,
 * `cis_3.0.1_aws`. Must stay in lock-step with the backend regex in
 * `api/src/backend/tasks/jobs/report.py::_CIS_VARIANT_RE`.
 *
 * The version chunk requires at least one dotted component so malformed
 * inputs like ``cis_5._aws``, ``cis_._aws`` or ``cis_5_aws`` are rejected
 * at the regex stage instead of reaching the comparator with phantom zeros.
 *
 * Uses positional groups (not named) so the regex works under ES5 target.
 * Group 1 = version string, group 2 = provider.
 */
const CIS_VARIANT_RE = /^cis_(\d+(?:\.\d+)+)_(.+)$/;

/**
 * From an arbitrary set of compliance_ids (as returned by the compliance
 * overview endpoint), return the subset of CIS variants that correspond to
 * the highest semantic version per provider.
 *
 * Why: the backend now only generates the CIS PDF for the latest version
 * per provider (see `_pick_latest_cis_variant` in report.py). This helper
 * mirrors that selection in the UI so only the "latest" CIS card exposes
 * the PDF download button; older variants keep the CSV option.
 *
 * A lexicographic sort would be wrong (`cis_1.10_kubernetes` must beat
 * `cis_1.2_kubernetes`), so the version chunk is parsed into a numeric
 * tuple. Malformed names are silently skipped.
 *
 * Non-CIS compliance_ids are ignored — the returned Set only contains
 * compliance_ids that satisfy `complianceId.startsWith("cis_")`.
 */
export const pickLatestCisPerProvider = (
  complianceIds: readonly string[],
): Set<string> => {
  const bestByProvider: Record<string, { key: number[]; id: string }> = {};

  const compareVersions = (a: number[], b: number[]): number => {
    const length = Math.max(a.length, b.length);
    for (let i = 0; i < length; i++) {
      // Use nullish coalescing — `||` would also collapse a legitimate 0.0
      // into 0 (harmless here, but semantically wrong for a version chunk
      // comparator). Missing trailing components are treated as `.0`.
      const diff = (a[i] ?? 0) - (b[i] ?? 0);
      if (diff !== 0) return diff;
    }
    return 0;
  };

  complianceIds.forEach((id) => {
    const match = id.match(CIS_VARIANT_RE);
    if (!match) return;

    const version = match[1];
    const provider = match[2];
    const parts = version.split(".").map((chunk: string) => Number(chunk));
    if (parts.some((n: number) => !Number.isFinite(n))) return;

    const current = bestByProvider[provider];
    if (!current || compareVersions(parts, current.key) > 0) {
      bestByProvider[provider] = { key: parts, id };
    }
  });

  const latest = new Set<string>();
  Object.keys(bestByProvider).forEach((provider) => {
    latest.add(bestByProvider[provider].id);
  });
  return latest;
};

/**
 * Resolve the report type for a compliance card, preferring the framework
 * name match and falling back to per-variant compliance_id detection.
 *
 * This is the entry point that call sites (ComplianceCard, compliance detail
 * page) should use so that both single-version frameworks (ENS/NIS2/CSA/
 * ThreatScore) and multi-variant frameworks (CIS) light up their PDF button
 * without duplicating the fallback logic.
 *
 * CIS is gated by `isLatestCisForProvider`: only the card representing the
 * highest CIS version per provider gets a PDF button, since the backend only
 * generates a single PDF per provider. Callers must compute the "latest" set
 * ahead of time via `pickLatestCisPerProvider` — this defaults to `false` so
 * forgetting to pass it fails closed (no phantom PDF button).
 */
export const getReportTypeForCompliance = (
  framework: string | undefined,
  complianceId: string | undefined,
  isLatestCisForProvider: boolean = false,
): ComplianceReportType | undefined => {
  const fromFramework = getReportTypeForFramework(framework);
  if (fromFramework) return fromFramework;
  if (isLatestCisForProvider) {
    return getReportTypeForComplianceId(complianceId);
  }
  return undefined;
};
