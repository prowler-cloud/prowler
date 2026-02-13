export const COMPLIANCE_WATCHLIST_OVERVIEW_TYPE = {
  WATCHLIST_OVERVIEW: "compliance-watchlist-overviews",
} as const;

type ComplianceWatchlistOverviewType =
  (typeof COMPLIANCE_WATCHLIST_OVERVIEW_TYPE)[keyof typeof COMPLIANCE_WATCHLIST_OVERVIEW_TYPE];

export interface ComplianceWatchlistOverviewAttributes {
  compliance_id: string;
  requirements_passed: number;
  requirements_failed: number;
  requirements_manual: number;
  total_requirements: number;
}

export interface ComplianceWatchlistOverview {
  type: ComplianceWatchlistOverviewType;
  id: string;
  attributes: ComplianceWatchlistOverviewAttributes;
}

export interface ComplianceWatchlistResponse {
  data: ComplianceWatchlistOverview[];
}
