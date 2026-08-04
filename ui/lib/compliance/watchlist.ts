import type {
  ComplianceCatalogEntry,
  ComplianceWatchlistBulkDiff,
  ComplianceWatchlistTarget,
} from "@/types/compliance-watchlist";
import { UNIVERSAL_PROVIDER_TYPE } from "@/types/compliance-watchlist";

export const MAX_WATCHLIST_BULK = 200;

export const IN_WATCHLIST_FILTER_KEY = "filter[in_watchlist]";

export const watchlistKey = (target: ComplianceWatchlistTarget): string =>
  `${target.providerType}:${target.complianceId}`;

export type ComplianceCatalogIndex = Map<string, ComplianceCatalogEntry>;

export const buildWatchlistIndex = (
  entries: ComplianceCatalogEntry[],
): ComplianceCatalogIndex =>
  new Map(entries.map((entry) => [watchlistKey(entry), entry]));

const universalKey = (complianceId: string): string =>
  watchlistKey({ complianceId, providerType: UNIVERSAL_PROVIDER_TYPE });

// Exact keys win. Universal and legacy suffixed ids fall back to the `*` row.
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

export const isFrameworkPinned = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): boolean => resolveCatalogEntry(index, target)?.inWatchlist === true;

export const resolveWatchlistEntryId = (
  index: ComplianceCatalogIndex,
  target: ComplianceWatchlistTarget,
): string | null =>
  resolveCatalogEntry(index, target)?.watchlistEntryId ?? null;

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

// Submit a diff so concurrent edits outside this selection are preserved.
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

export const formatWatchlistBulkSummary = (summary: {
  added: number;
  removed: number;
}): string => {
  const parts: string[] = [];
  if (summary.added > 0) parts.push(`${summary.added} added`);
  if (summary.removed > 0) parts.push(`${summary.removed} removed`);
  return parts.length > 0 ? parts.join(" · ") : "No changes";
};
