import type { ActionErrorResult } from "@/lib/action-errors";
import type { RequirementStatus } from "@/types/compliance";
import type { KnownProviderType, ProviderType } from "@/types/providers";

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
  /** Narrowed to the known set: the breakdown only renders providers the UI
   *  ships display names and icons for. */
  provider: KnownProviderType;
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

// Types for the Cloud-only cross-account compliance roll-up, backed by
// GET /cross-account-compliance-overviews (one regular per-provider framework
// aggregated across the latest scan of every account of a single provider
// type; same server-side roll-up rules as the cross-provider endpoint, with
// the column axis being the account instead of the provider type).

export const CROSS_ACCOUNT_OVERVIEW_TYPE =
  "cross-account-compliance-overviews" as const;

/** Contributing account (Provider) metadata, sorted by alias server-side. */
export interface CrossAccountAccountRef {
  id: string;
  uid: string;
  alias: string | null;
}

/** Requirement status per account, keyed by Provider UUID. */
export type AccountStatusMap = Record<string, CrossProviderStatus>;

export interface CrossAccountRequirementData {
  id: string;
  name: string;
  description: string;
  /** Framework-specific metadata list from the per-provider template
   *  (already unwrapped — same shape the per-scan mappers consume). */
  attributes: unknown[];
  status: CrossProviderStatus;
  accounts: AccountStatusMap;
  /** Single flat list — every account shares the provider type. */
  check_ids?: string[];
}

export interface CrossAccountOverviewAttributes {
  compliance_id: string;
  provider_type: string;
  framework: string;
  name: string;
  version: string;
  description: string;
  accounts: CrossAccountAccountRef[];
  scan_ids: string[];
  /** Provider UUID → scan UUIDs aggregated for that account. */
  scan_ids_by_account: Record<string, string[]>;
  requirements_passed: number;
  requirements_failed: number;
  requirements_manual: number;
  total_requirements: number;
  requirements: CrossAccountRequirementData[];
}

export interface CrossAccountOverviewData {
  type: typeof CROSS_ACCOUNT_OVERVIEW_TYPE;
  id: string;
  attributes: CrossAccountOverviewAttributes;
}

export interface CrossAccountOverviewResponse {
  data: CrossAccountOverviewData;
}

/** Result variants reuse the cross-provider status constants so the shared
 *  error components (CrossProviderErrorAlert) work unchanged. */
export type CrossAccountOverviewResult =
  | {
      status: typeof CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS;
      response: CrossAccountOverviewResponse;
    }
  | CrossProviderOverviewActionErrorResult
  | CrossProviderOverviewLoadErrorResult;

/** Filters accepted by the cross-account endpoint (comma-joined). */
export interface CrossAccountApiFilters {
  scanIds?: string[];
  providerIds?: string;
  providerGroups?: string;
}

/** Cross-account context joined onto a mapped requirement, keyed by the
 *  composed requirement name the per-scan mappers produce. */
export interface CrossAccountRequirementExtras {
  requirementId: string;
  accounts: AccountStatusMap;
  checkIds: string[];
  scanIdsByAccount: Record<string, string[]>;
}

/** Card data for the per-provider frameworks section of the Cross-Provider
 *  tab: one regular framework of one provider type, aggregatable across
 *  that type's accounts. */
export interface CrossAccountFrameworkEntry {
  /** Regular framework id used as filter[compliance_id] (e.g. cis_2.0_aws). */
  complianceId: string;
  /** Framework display name; also the [compliancetitle] path segment and the
   *  key getComplianceIcon resolves the framework icon from. */
  title: string;
  version: string;
  providerType: KnownProviderType;
  accountCount: number;
}

export interface AccountBreakdownEntry {
  id: string;
  label: string;
  pass: number;
  fail: number;
  manual: number;
  total: number;
  /** 0-100 pass percentage over non-manual requirements. */
  score: number;
}
