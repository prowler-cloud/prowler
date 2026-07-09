import type { ActionErrorResult } from "@/lib/action-errors";
import type { RequirementStatus } from "@/types/compliance";
import type { ProviderType } from "@/types/providers";

// Types for the Cloud-only cross-provider compliance roll-up, backed by
// GET /cross-provider-compliance-overviews (one universal framework
// aggregated across one scan per compatible provider; roll-up status is
// computed server-side as FAIL > PASS > MANUAL).

export const COMPLIANCE_TAB = {
  PER_SCAN: "per-scan",
  CROSS_PROVIDER: "cross-provider",
} as const;

export type ComplianceTab =
  (typeof COMPLIANCE_TAB)[keyof typeof COMPLIANCE_TAB];

export const CROSS_PROVIDER_OVERVIEW_TYPE =
  "cross-provider-compliance-overviews" as const;

/** Roll-up statuses the endpoint emits (never "No findings"). */
export type CrossProviderStatus = Extract<
  RequirementStatus,
  "PASS" | "FAIL" | "MANUAL"
>;

export type ProviderStatusMap = Partial<
  Record<ProviderType, CrossProviderStatus>
>;

export type ProviderCheckIdsMap = Partial<Record<ProviderType, string[]>>;

export type ProviderScanIdsMap = Partial<Record<ProviderType, string[]>>;

export interface CrossProviderRequirementData {
  id: string;
  name: string;
  description: string;
  /** Free-form per-requirement metadata from the universal JSON (e.g. CSA
   *  exposes Section/CCMLite; DORA exposes Chapter/Article). */
  attributes: Record<string, unknown>;
  status: CrossProviderStatus;
  providers: ProviderStatusMap;
  check_ids_by_provider?: ProviderCheckIdsMap;
}

export interface CrossProviderOverviewAttributes {
  compliance_id: string;
  framework: string;
  name: string;
  version: string;
  description: string;
  /** Provider types the universal framework declares checks for. */
  compatible_providers: string[];
  /** Provider types of the scans used as aggregation input. */
  requested_providers: string[];
  /** Provider types that contributed at least one row after RBAC/filters. */
  providers: string[];
  scan_ids: string[];
  /** Provider type → scan UUIDs aggregated (a type can have N accounts). */
  scan_ids_by_provider: ProviderScanIdsMap;
  requirements_passed: number;
  requirements_failed: number;
  requirements_manual: number;
  total_requirements: number;
  requirements: CrossProviderRequirementData[];
}

export interface CrossProviderOverviewData {
  type: typeof CROSS_PROVIDER_OVERVIEW_TYPE;
  id: string;
  attributes: CrossProviderOverviewAttributes;
}

export interface CrossProviderOverviewResponse {
  data: CrossProviderOverviewData;
}

export const CROSS_PROVIDER_OVERVIEW_RESULT_STATUS = {
  SUCCESS: "success",
  ACTION_ERROR: "action-error",
  LOAD_ERROR: "load-error",
} as const;

export type CrossProviderOverviewResultStatus =
  (typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS)[keyof typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS];

export const CROSS_PROVIDER_OVERVIEW_LOAD_ERROR_MESSAGE =
  "Could not load cross-provider compliance data. Try again later.";

export interface CrossProviderOverviewSuccessResult {
  status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS;
  response: CrossProviderOverviewResponse;
}

export interface CrossProviderOverviewActionErrorResult {
  status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.ACTION_ERROR;
  result: ActionErrorResult;
}

export interface CrossProviderOverviewLoadErrorResult {
  status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.LOAD_ERROR;
  message: string;
}

export type CrossProviderOverviewResult =
  | CrossProviderOverviewSuccessResult
  | CrossProviderOverviewActionErrorResult
  | CrossProviderOverviewLoadErrorResult;

/** Filters accepted by every cross-provider endpoint (comma-joined). */
export interface CrossProviderApiFilters {
  scanIds?: string[];
  providerTypes?: string;
  providerIds?: string;
  providerGroups?: string;
  regions?: string;
}

/** Cross-provider context joined onto a mapped requirement, keyed by the
 *  composed requirement name the per-scan mappers produce. */
export interface CrossProviderRequirementExtras {
  requirementId: string;
  providers: ProviderStatusMap;
  checkIdsByProvider: ProviderCheckIdsMap;
  scanIdsByProvider: ProviderScanIdsMap;
}

/** Card-ready framework roll-up shared by the overview grid (producer) and
 *  `CrossProviderFrameworkCard` (props), so the `{...summary}` spread can
 *  never drift between the two. */
export interface CrossProviderFrameworkSummary {
  complianceId: string;
  title: string;
  version: string;
  description: string;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  totalRequirements: number;
  providerBreakdown: ProviderBreakdownEntry[];
}

export interface ProviderBreakdownEntry {
  provider: ProviderType;
  pass: number;
  fail: number;
  manual: number;
  total: number;
  /** 0-100 pass percentage over non-manual requirements. */
  score: number;
  /** Compatible with the framework but no scan contributed. */
  unscanned: boolean;
}

/** A previously generated PDF matching the current filters, downloadable
 *  immediately without polling. */
export interface LatestCrossProviderPdf {
  taskId: string;
  filename?: string;
  completedAt?: string;
}
