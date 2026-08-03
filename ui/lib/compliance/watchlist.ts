import type {
  ComplianceCatalogEntry,
  ComplianceWatchlistBulkDiff,
  ComplianceWatchlistTarget,
} from "@/types/compliance-watchlist";
import { UNIVERSAL_PROVIDER_TYPE } from "@/types/compliance-watchlist";

/** Mirrors the API's MAX_WATCHLIST_BULK so the modal can refuse an oversized
 *  diff locally instead of round-tripping into a `bulk_limit_exceeded`. */
export const MAX_WATCHLIST_BULK = 200;

/**
 * Narrows a pre-existing compliance endpoint to the tenant's watchlist.
 *
 * Opt-in on the API: an endpoint that does not receive it answers exactly as it
 * did before the watchlist existed, which is why a surface that forgets to send
 * it silently keeps listing every framework.
 */
export const IN_WATCHLIST_FILTER_KEY = "filter[in_watchlist]";

/**
 * Canonical key of a pinned framework, identical to the catalog entry's `id`.
 * Display names are never part of it: `compliance_id` alone is ambiguous,
 * because several provider types declare the same one.
 */
export const watchlistKey = (target: ComplianceWatchlistTarget): string =>
  `${target.providerType}:${target.complianceId}`;

export type ComplianceCatalogIndex = Map<string, ComplianceCatalogEntry>;

/** Index the catalog so every surface can resolve a card's pinned state by
 *  key instead of scanning the list once per card. */
export const buildWatchlistIndex = (
  entries: ComplianceCatalogEntry[],
): ComplianceCatalogIndex =>
  new Map(entries.map((entry) => [watchlistKey(entry), entry]));

const universalKey = (complianceId: string): string =>
  watchlistKey({ complianceId, providerType: UNIVERSAL_PROVIDER_TYPE });

/**
 * The catalog row a target maps to.
 *
 * A universal framework is one card across every compatible provider type, so
 * the catalog keys it under `*` — but surfaces legitimately ask for it with a
 * concrete type (the per-scan view of an AWS scan lists CIS Controls under
 * `aws`). Falling back to `*` is what makes all three surfaces agree on one row
 * instead of each looking up a key the catalog never emits. The exact key is
 * tried first regardless: a universal framework never also has a concrete-type
 * row, so nothing is lost, and a provider-scoped row can never be shadowed by a
 * universal one that happens to share its `compliance_id`.
 *
 * The last attempt peels a legacy per-provider suffix (`csa_ccm_4.0_aws`, from
 * scans predating the universal frameworks) the same way the API does on write.
 * Without it such a card read as unpinned no matter how often it was pinned,
 * because the row it created lives under the bare name. It can only ever match
 * a `*` key, so a provider-scoped framework that happens to end in its own
 * provider type (`cis_1.4_aws`, `gdpr_aws`) is unaffected.
 */
export const resolveCatalogEntry = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): ComplianceCatalogEntry | undefined => {
  const exact =
    index.get(watchlistKey(target)) ??
    index.get(universalKey(target.complianceId));
  if (exact) return exact;

  const legacySuffix = `_${target.providerType}`;
  if (!target.providerType || !target.complianceId.endsWith(legacySuffix)) {
    return undefined;
  }
  return index.get(
    universalKey(target.complianceId.slice(0, -legacySuffix.length)),
  );
};

/** A framework the catalog does not know about is treated as unpinned rather
 *  than as an error: the catalog is scoped to the provider types the tenant
 *  actually has, and a surface may render a framework outside that scope. */
export const isFrameworkPinned = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): boolean => resolveCatalogEntry(index, target)?.inWatchlist === true;

export const resolveWatchlistEntryId = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): string | null =>
  resolveCatalogEntry(index, target)?.watchlistEntryId ?? null;

/**
 * The pair a write must carry for this target. Universal frameworks collapse
 * onto `*`, mirroring what the API stores, so a card never writes one key and
 * reads back another — the mismatch that made an add and a remove of the same
 * framework land in one bulk call and cancel out.
 */
export const resolveWatchlistTarget = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): ComplianceWatchlistTarget => {
  const entry = resolveCatalogEntry(index, target);
  return entry
    ? { complianceId: entry.complianceId, providerType: entry.providerType }
    : target;
};

const dedupeByKey = (
  targets: ComplianceWatchlistTarget[],
): Map<string, ComplianceWatchlistTarget> =>
  new Map(targets.map((target) => [watchlistKey(target), target]));

/**
 * Diff the bulk modal submits: what the user selected minus what was already
 * pinned, and vice versa. Computed against the initial state rather than sent
 * as a full replacement so a concurrent edit by another member only loses the
 * frameworks this user actually touched.
 */
export const computeWatchlistDiff = (
  initial: ComplianceWatchlistTarget[],
  selected: ComplianceWatchlistTarget[],
): ComplianceWatchlistBulkDiff => {
  const initialByKey = dedupeByKey(initial);
  const selectedByKey = dedupeByKey(selected);

  const add: ComplianceWatchlistTarget[] = [];
  selectedByKey.forEach((target, key) => {
    if (!initialByKey.has(key)) add.push(target);
  });

  const remove: ComplianceWatchlistTarget[] = [];
  initialByKey.forEach((target, key) => {
    if (!selectedByKey.has(key)) remove.push(target);
  });

  return { add, remove };
};

export const exceedsWatchlistBulkLimit = (
  diff: ComplianceWatchlistBulkDiff,
): boolean => diff.add.length + diff.remove.length > MAX_WATCHLIST_BULK;

export const isEmptyWatchlistDiff = (
  diff: ComplianceWatchlistBulkDiff,
): boolean => diff.add.length === 0 && diff.remove.length === 0;

/** One-line summary of what the bulk call changed, for the success toast. */
export const formatWatchlistBulkSummary = (summary: {
  added: number;
  removed: number;
}): string => {
  const parts: string[] = [];
  if (summary.added > 0) parts.push(`${summary.added} added`);
  if (summary.removed > 0) parts.push(`${summary.removed} removed`);
  return parts.length > 0 ? parts.join(" · ") : "No changes";
};
