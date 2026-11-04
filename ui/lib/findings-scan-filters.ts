interface ScanDateSource {
  id: string;
  attributes?: {
    // Findings are written throughout the run, so the range spans both
    // timestamps, not the scan's `inserted_at` (when the row was created).
    started_at?: string | null;
    completed_at?: string | null;
  };
}

interface ResolveFindingScanDateFiltersOptions {
  filters: Record<string, string>;
  scans: ScanDateSource[];
  loadScan: (scanId: string) => Promise<ScanDateSource | null | undefined>;
}

const INSERTED_AT_FILTER_KEYS = [
  "filter[inserted_at]",
  "filter[inserted_at__date]",
  "filter[inserted_at__gte]",
  "filter[inserted_at__lte]",
] as const;

export function getScanFilterIds(filters: Record<string, string>): string[] {
  const scanIds = filters["filter[scan__in]"] || filters["filter[scan]"] || "";
  return Array.from(new Set(scanIds.split(",").filter(Boolean)));
}

function formatScanDate(dateTime?: string): string | null {
  if (!dateTime) return null;
  const [date] = dateTime.split("T");
  return date?.trim() || null;
}

function hasInsertedAtFilter(filters: Record<string, string>): boolean {
  return INSERTED_AT_FILTER_KEYS.some((key) => Boolean(filters[key]));
}

// The latest view reads summaries written seconds after a scan completes.
// shortcut: fixed grace period, replace with a "summaries ready" flag on Scan if this ships.
const SCAN_SUMMARY_GRACE_MS = 2 * 60 * 1000;

/** Whether a completed scan's summaries have had time to reach the latest view. */
export function isScanSettled(
  completedAt: string | null | undefined,
  now: number,
): boolean {
  return (
    Boolean(completedAt) &&
    now - Date.parse(completedAt as string) >= SCAN_SUMMARY_GRACE_MS
  );
}

/**
 * The latest view reads settled scans only, so until the first one settles it
 * is empty. Point it at the early scans (running or just finished), which store
 * findings as they go.
 */
// shortcut: decided tenant-wide, so a new provider scanned next to an already
// scanned one waits for completion; per-provider fallback if this ships.
export function getEarlyFindingScanFilters(
  filters: Record<string, string>,
  hasSettledScan: boolean,
  earlyScanIds: string[],
): Record<string, string> {
  if (
    hasSettledScan ||
    earlyScanIds.length === 0 ||
    getScanFilterIds(filters).length > 0 ||
    hasInsertedAtFilter(filters)
  ) {
    return filters;
  }

  return { ...filters, "filter[scan__in]": earlyScanIds.join(",") };
}

export function buildFindingScanDateFilters(
  scanDateTimes: string[],
): Record<string, string> {
  const dates = Array.from(
    new Set(scanDateTimes.map(formatScanDate).filter(Boolean)),
  ).sort() as string[];

  if (dates.length === 0) {
    return {};
  }

  if (dates.length === 1) {
    return {
      "filter[inserted_at]": dates[0],
    };
  }

  return {
    "filter[inserted_at__gte]": dates[0],
    "filter[inserted_at__lte]": dates[dates.length - 1],
  };
}

export async function resolveFindingScanDateFilters({
  filters,
  scans,
  loadScan,
}: ResolveFindingScanDateFiltersOptions): Promise<Record<string, string>> {
  const scanIds = getScanFilterIds(filters);

  if (scanIds.length === 0 || hasInsertedAtFilter(filters)) {
    return filters;
  }

  const scansById = new Map(scans.map((scan) => [scan.id, scan]));
  const missingScanIds = scanIds.filter((scanId) => !scansById.has(scanId));

  if (missingScanIds.length > 0) {
    const missingScans = await Promise.all(
      missingScanIds.map((scanId) => loadScan(scanId)),
    );

    missingScans.forEach((scan) => {
      if (scan) {
        scansById.set(scan.id, scan);
      }
    });
  }

  const scanDateTimes = scanIds
    .flatMap((scanId) => {
      const attributes = scansById.get(scanId)?.attributes;
      // A running scan keeps writing findings, so its range ends today.
      const endedAt =
        attributes?.completed_at ||
        (attributes?.started_at ? new Date().toISOString() : undefined);
      return [attributes?.started_at, endedAt];
    })
    .filter((dateTime): dateTime is string => Boolean(dateTime));

  const dateFilters = buildFindingScanDateFilters(scanDateTimes);

  if (Object.keys(dateFilters).length === 0) {
    return filters;
  }

  return {
    ...filters,
    ...dateFilters,
  };
}
