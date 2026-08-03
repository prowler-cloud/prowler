// Types for the tenant-wide Compliance Watchlist (Prowler Cloud only), backed
// by GET /compliance-catalog and the /compliance-watchlist-entries family.
//
// A pinned framework is keyed by what the UI renders as one card, never by
// display name. For a provider-scoped framework that is
// `(compliance_id, provider_type)` — one card per provider type, which is what
// the cross-account section lists. A universal framework (DORA, CSA CCM, CIS
// Controls) is a *single* card across every compatible type, so it is keyed
// `(compliance_id, "*")` and pinned once no matter which surface pinned it.

export const COMPLIANCE_CATALOG_ENTRY_TYPE =
  "compliance-catalog-entries" as const;

export const COMPLIANCE_WATCHLIST_ENTRY_TYPE =
  "compliance-watchlist-entries" as const;

export const COMPLIANCE_WATCHLIST_BULK_TYPE =
  "compliance-watchlist-bulk" as const;

/** Sentinel the API stores in `provider_type` for universal frameworks. */
export const UNIVERSAL_PROVIDER_TYPE = "*";

/** Which section a catalog card belongs to: `universal` cards are the
 *  cross-provider section's, `provider` cards the cross-account section's. The
 *  per-scan view shows both. */
export const WATCHLIST_SCOPE = {
  UNIVERSAL: "universal",
  PROVIDER: "provider",
} as const;

export type WatchlistScope =
  (typeof WATCHLIST_SCOPE)[keyof typeof WATCHLIST_SCOPE];

/** The watchlist's only key. `providerType` is `"*"` for universal
 *  frameworks, which the organization pins once. */
export interface ComplianceWatchlistTarget {
  complianceId: string;
  providerType: string;
}

/** One card in the catalog: a framework the tenant may pin, with the metadata
 *  a card needs and its current watchlist state. */
export interface ComplianceCatalogEntry extends ComplianceWatchlistTarget {
  /** Server-side id, `{provider_type}:{compliance_id}` — so `*:dora_2022_2554`
   *  for a universal framework. */
  id: string;
  scope: WatchlistScope;
  /** Onboarded provider types this card covers: one for a provider-scoped
   *  framework, every compatible one for a universal card. */
  providerTypes: string[];
  framework: string;
  name: string;
  version: string;
  description: string;
  totalRequirements: number;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  /** 0-100, or null when the framework has no scan data yet. */
  score: number | null;
  /** False means "never scanned" — render that, not a red 0%. */
  hasData: boolean;
  inWatchlist: boolean;
  /** DELETE target for unpinning, so no lookup is needed first. */
  watchlistEntryId: string | null;
}

/** Root meta of GET /compliance-catalog, counted before filtering so one
 *  request feeds both the "N Total Entries" and "(x of N)" counters. */
export interface ComplianceCatalogMeta {
  totalEntries: number;
  watchlistCount: number;
  eligibleProviderTypes: string[];
}

export interface ComplianceCatalog {
  entries: ComplianceCatalogEntry[];
  meta: ComplianceCatalogMeta;
}

/** Payload of POST /compliance-watchlist-entries/bulk. Both lists are
 *  idempotent and removals are not validated against the catalog. */
export interface ComplianceWatchlistBulkDiff {
  add: ComplianceWatchlistTarget[];
  remove: ComplianceWatchlistTarget[];
}

/** Root meta the bulk endpoint answers with. */
export interface ComplianceWatchlistBulkSummary {
  added: number;
  alreadyPresent: number;
  removed: number;
  notPresent: number;
  watchlistCount: number;
}

/** Whether a card renders as pinned. Binary by construction: every card —
 *  universal ones included — maps to exactly one watchlist entry, so there is
 *  no half-pinned state to represent. */
export const WATCHLIST_PIN_STATE = {
  PINNED: "pinned",
  UNPINNED: "unpinned",
} as const;

export type WatchlistPinState =
  (typeof WATCHLIST_PIN_STATE)[keyof typeof WATCHLIST_PIN_STATE];

export interface ComplianceWatchlistActionResult {
  success?: string;
  error?: string;
  summary?: ComplianceWatchlistBulkSummary;
}
