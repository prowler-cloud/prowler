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
  dateSource?: FindingScanDateSource;
}

export const FINDING_SCAN_DATE_SOURCE_PARAM = "scanDateSource";

export const FINDING_SCAN_DATE_SOURCE = {
  SCAN_ACTION: "scan-action",
} as const;

type FindingScanDateSource =
  `${typeof FINDING_SCAN_DATE_SOURCE.SCAN_ACTION}:${string}`;

const SCAN_ACTION_DATE_PREFIX =
  `${FINDING_SCAN_DATE_SOURCE.SCAN_ACTION}:` as const;

export function buildFindingScanDateSource(
  displayDate: string,
): FindingScanDateSource {
  return `${SCAN_ACTION_DATE_PREFIX}${displayDate}`;
}

export function parseFindingScanDateSource(
  value: string | string[] | undefined,
): FindingScanDateSource | undefined {
  const candidate = Array.isArray(value) ? value[0] : value;

  return candidate?.startsWith(SCAN_ACTION_DATE_PREFIX) &&
    candidate.length > SCAN_ACTION_DATE_PREFIX.length
    ? (candidate as FindingScanDateSource)
    : undefined;
}

const INSERTED_AT_FILTER_KEYS = [
  "filter[inserted_at]",
  "filter[inserted_at__date]",
  "filter[inserted_at__gte]",
  "filter[inserted_at__lte]",
] as const;

export const FINDING_SCAN_DATE_PROVENANCE_FILTER_KEYS = [
  "filter[scan__in]",
  "filter[scan]",
  ...INSERTED_AT_FILTER_KEYS,
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
  dateSource,
}: ResolveFindingScanDateFiltersOptions): Promise<Record<string, string>> {
  const scanIds = getScanFilterIds(filters);
  const scanActionDisplayDate = dateSource?.slice(
    SCAN_ACTION_DATE_PREFIX.length,
  );
  const isScanActionDate =
    Boolean(scanActionDisplayDate) &&
    filters["filter[inserted_at]"] === scanActionDisplayDate;

  if (
    scanIds.length === 0 ||
    (hasInsertedAtFilter(filters) && !isScanActionDate)
  ) {
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

  const apiFilters = isScanActionDate
    ? Object.fromEntries(
        Object.entries(filters).filter(([key]) =>
          INSERTED_AT_FILTER_KEYS.every((dateKey) => dateKey !== key),
        ),
      )
    : filters;

  return {
    ...apiFilters,
    ...dateFilters,
  };
}
