interface ScanDateSource {
  id: string;
  attributes?: {
    // Findings are persisted when the scan finishes, so their `inserted_at`
    // aligns with the scan's `completed_at` — not the scan's `inserted_at`
    // (which is when the scan row was first created and can fall on a
    // different UTC day for scans that cross midnight).
    completed_at?: string;
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

function getScanFilterIds(filters: Record<string, string>): string[] {
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

export function buildFindingScanDateFilters(
  scanCompletedAtValues: string[],
): Record<string, string> {
  const dates = Array.from(
    new Set(scanCompletedAtValues.map(formatScanDate).filter(Boolean)),
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

  const scanCompletedAtValues = scanIds
    .map((scanId) => scansById.get(scanId)?.attributes?.completed_at)
    .filter((completedAt): completedAt is string => Boolean(completedAt));

  const dateFilters = buildFindingScanDateFilters(scanCompletedAtValues);

  if (Object.keys(dateFilters).length === 0) {
    return filters;
  }

  return {
    ...filters,
    ...dateFilters,
  };
}
