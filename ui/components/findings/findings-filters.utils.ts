import type { FilterChip } from "@/components/filters/filter-summary-strip";
import { formatLabel, getCategoryLabel, getGroupLabel } from "@/lib/categories";
import { getScanEntityLabel } from "@/lib/helper-filters";
import { FINDING_STATUS_DISPLAY_NAMES } from "@/types";
import { FilterParam } from "@/types/filters";
import { getProviderDisplayName, ProviderProps } from "@/types/providers";
import { ScanEntity } from "@/types/scans";
import { SEVERITY_DISPLAY_NAMES } from "@/types/severities";

interface GetFindingsFilterDisplayValueOptions {
  providers?: ProviderProps[];
  scans?: Array<{ [scanId: string]: ScanEntity }>;
}

const FINDING_DELTA_DISPLAY_NAMES: Record<string, string> = {
  new: "New",
  changed: "Changed",
};

function getProviderAccountDisplayValue(
  providerId: string,
  providers: ProviderProps[],
): string {
  const provider = providers.find((item) => item.id === providerId);
  if (!provider) {
    return providerId;
  }

  return provider.attributes.alias || provider.attributes.uid || providerId;
}

function getScanDisplayValue(
  scanId: string,
  scans: Array<{ [scanId: string]: ScanEntity }>,
): string {
  const scan = scans.find((item) => item[scanId])?.[scanId];
  if (!scan) {
    return scanId;
  }

  return getScanEntityLabel(scan) || scanId;
}

export function getFindingsFilterDisplayValue(
  filterKey: string,
  value: string,
  options: GetFindingsFilterDisplayValueOptions = {},
): string {
  if (!value) return value;
  if (filterKey === "filter[provider_type__in]") {
    return getProviderDisplayName(value);
  }
  if (filterKey === "filter[provider_id__in]") {
    return getProviderAccountDisplayValue(value, options.providers || []);
  }
  if (filterKey === "filter[scan__in]" || filterKey === "filter[scan]") {
    return getScanDisplayValue(value, options.scans || []);
  }
  if (filterKey === "filter[severity__in]") {
    return (
      SEVERITY_DISPLAY_NAMES[
        value.toLowerCase() as keyof typeof SEVERITY_DISPLAY_NAMES
      ] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[status__in]") {
    return (
      FINDING_STATUS_DISPLAY_NAMES[
        value as keyof typeof FINDING_STATUS_DISPLAY_NAMES
      ] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[delta__in]" || filterKey === "filter[delta]") {
    return (
      FINDING_DELTA_DISPLAY_NAMES[value.toLowerCase()] ?? formatLabel(value)
    );
  }
  if (filterKey === "filter[category__in]") {
    return getCategoryLabel(value);
  }
  if (filterKey === "filter[resource_groups__in]") {
    return getGroupLabel(value);
  }
  if (
    filterKey === "filter[inserted_at]" ||
    filterKey === "filter[inserted_at__gte]" ||
    filterKey === "filter[inserted_at__lte]"
  ) {
    return value;
  }

  return formatLabel(value);
}

/**
 * Maps raw filter param keys (e.g. "filter[severity__in]") to human-readable labels.
 * Used to render chips in the FilterSummaryStrip.
 * Typed as Record<FilterParam, string> so TypeScript enforces exhaustiveness — any
 * addition to FilterParam will cause a compile error here if the label is missing.
 */
export const FILTER_KEY_LABELS: Record<FilterParam, string> = {
  "filter[provider_type__in]": "Provider",
  "filter[provider_id__in]": "Account",
  "filter[severity__in]": "Severity",
  "filter[status__in]": "Status",
  "filter[delta__in]": "Delta",
  "filter[delta]": "Delta",
  "filter[region__in]": "Region",
  "filter[service__in]": "Service",
  "filter[resource_type__in]": "Resource Type",
  "filter[category__in]": "Category",
  "filter[resource_groups__in]": "Resource Group",
  "filter[scan]": "Scan",
  "filter[scan__in]": "Scan",
  "filter[scan_id]": "Scan",
  "filter[scan_id__in]": "Scan",
  "filter[inserted_at]": "Date",
  "filter[muted]": "Muted",
};

interface BuildFindingsFilterChipsOptions {
  providers?: ProviderProps[];
  scans?: Array<{ [scanId: string]: ScanEntity }>;
}

/**
 * Builds the chips displayed in the FilterSummaryStrip from a pendingFilters map.
 *
 * - One chip per individual value (not one per key), so a multi-select filter
 *   produces multiple chips.
 * - Silently skips the default `filter[muted]=false` so it doesn't appear as a
 *   user-applied filter.
 * - Falls back to the raw key as label for unmapped keys, so an unexpected
 *   param still surfaces instead of disappearing.
 */
export function buildFindingsFilterChips(
  pendingFilters: Record<string, string[]>,
  options: BuildFindingsFilterChipsOptions = {},
): FilterChip[] {
  const chips: FilterChip[] = [];

  Object.entries(pendingFilters).forEach(([key, values]) => {
    if (!values || values.length === 0) return;
    const label = FILTER_KEY_LABELS[key as FilterParam] ?? key;
    values.forEach((value) => {
      if (key === "filter[muted]" && value === "false") return;
      chips.push({
        key,
        label,
        value,
        displayValue: getFindingsFilterDisplayValue(key, value, options),
      });
    });
  });

  return chips;
}
