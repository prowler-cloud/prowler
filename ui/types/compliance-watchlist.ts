export const COMPLIANCE_CATALOG_ENTRY_TYPE =
  "compliance-catalog-entries" as const;

export const COMPLIANCE_WATCHLIST_ENTRY_TYPE =
  "compliance-watchlist-entries" as const;

export const COMPLIANCE_WATCHLIST_BULK_TYPE =
  "compliance-watchlist-bulk" as const;

export const UNIVERSAL_PROVIDER_TYPE = "*";

export const WATCHLIST_SCOPE = {
  UNIVERSAL: "universal",
  PROVIDER: "provider",
} as const;

export type WatchlistScope =
  (typeof WATCHLIST_SCOPE)[keyof typeof WATCHLIST_SCOPE];

export interface ComplianceWatchlistTarget {
  complianceId: string;
  providerType: string;
}

export interface ComplianceCatalogEntry extends ComplianceWatchlistTarget {
  id: string;
  scope: WatchlistScope;
  providerTypes: string[];
  framework: string;
  name: string;
  version: string;
  description: string;
  totalRequirements: number;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  score: number | null;
  hasData: boolean;
  inWatchlist: boolean;
  watchlistEntryId: string | null;
}

export interface ComplianceCatalogMeta {
  totalEntries: number;
  watchlistCount: number;
  eligibleProviderTypes: string[];
}

export interface ComplianceCatalog {
  entries: ComplianceCatalogEntry[];
  meta: ComplianceCatalogMeta;
}

export interface FindingComplianceFramework {
  id: string;
  complianceId: string;
  providerType: string;
  scope: WatchlistScope;
  framework: string;
  name: string;
  version: string;
  inWatchlist: boolean;
}

export interface FindingComplianceFrameworksResult {
  frameworks: FindingComplianceFramework[];
  unavailable: boolean;
}

export interface ComplianceWatchlistBulkDiff {
  add: ComplianceWatchlistTarget[];
  remove: ComplianceWatchlistTarget[];
}

export interface ComplianceWatchlistBulkSummary {
  added: number;
  alreadyPresent: number;
  removed: number;
  notPresent: number;
  watchlistCount: number;
}

export const WATCHLIST_PIN_STATE = {
  PINNED: "pinned",
  UNPINNED: "unpinned",
} as const;

export type WatchlistPinState =
  (typeof WATCHLIST_PIN_STATE)[keyof typeof WATCHLIST_PIN_STATE];

interface ComplianceWatchlistActionSuccess {
  success: string;
  error?: never;
  summary?: ComplianceWatchlistBulkSummary;
}

interface ComplianceWatchlistActionError {
  success?: never;
  error: string;
  summary?: never;
}

export type ComplianceWatchlistActionResult =
  | ComplianceWatchlistActionSuccess
  | ComplianceWatchlistActionError;
