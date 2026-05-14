/**
 * Per-tab persistence for finding groups the user just muted, used by the
 * findings table to keep a row hidden across a fast page reload while the
 * server-side reaggregation (Celery chain queued by POST /mute-rules) is
 * still in flight.
 *
 * Storage is `sessionStorage` (per-tab; closing the tab wipes it). Cross-tab
 * consistency is intentionally out of scope — the worst case is that another
 * tab keeps showing the row until the server data refreshes naturally.
 */

const STORAGE_KEY = "prowler:optimistic-muted-groups";

/** Default time-to-live for an optimistic entry. ~90s gives plenty of headroom
 * over the typical Celery reaggregation window. */
export const OPTIMISTIC_MUTED_GROUPS_TTL_MS = 90_000;

interface StoredEntry {
  expiresAt: number;
}

type StoredMap = Record<string, StoredEntry>;

function safeGetStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function readMap(): StoredMap {
  const storage = safeGetStorage();
  if (!storage) return {};
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed as StoredMap;
    return {};
  } catch {
    return {};
  }
}

function writeMap(map: StoredMap): void {
  const storage = safeGetStorage();
  if (!storage) return;
  try {
    if (Object.keys(map).length === 0) {
      storage.removeItem(STORAGE_KEY);
    } else {
      storage.setItem(STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Quota exceeded or storage disabled — silently ignore.
  }
}

function pruneExpired(
  map: StoredMap,
  now: number,
): {
  pruned: StoredMap;
  changed: boolean;
} {
  let changed = false;
  const pruned: StoredMap = {};
  for (const [checkId, entry] of Object.entries(map)) {
    if (entry?.expiresAt && entry.expiresAt > now) {
      pruned[checkId] = entry;
    } else {
      changed = true;
    }
  }
  return { pruned, changed };
}

/** Return the set of currently-active optimistic checkIds. Side effect:
 * silently removes expired entries from storage. */
export function loadOptimisticallyMutedCheckIds(
  now: number = Date.now(),
): Set<string> {
  const map = readMap();
  const { pruned, changed } = pruneExpired(map, now);
  if (changed) writeMap(pruned);
  return new Set(Object.keys(pruned));
}

/** Mark each checkId as optimistically muted, refreshing its TTL. */
export function persistOptimisticallyMutedCheckIds(
  checkIds: Iterable<string>,
  now: number = Date.now(),
): void {
  const ids = Array.from(checkIds);
  if (ids.length === 0) return;
  const { pruned } = pruneExpired(readMap(), now);
  const expiresAt = now + OPTIMISTIC_MUTED_GROUPS_TTL_MS;
  for (const id of ids) {
    pruned[id] = { expiresAt };
  }
  writeMap(pruned);
}

/** Drop the listed checkIds from storage (e.g. after the server payload no
 * longer mentions them). No-op for entries that aren't there. */
export function removePersistedOptimisticEntries(
  checkIds: Iterable<string>,
): void {
  const ids = Array.from(checkIds);
  if (ids.length === 0) return;
  const map = readMap();
  let changed = false;
  for (const id of ids) {
    if (id in map) {
      delete map[id];
      changed = true;
    }
  }
  if (changed) writeMap(map);
}

/** Wipe every optimistic entry. Mainly useful for tests. */
export function clearAllOptimisticEntries(): void {
  writeMap({});
}
