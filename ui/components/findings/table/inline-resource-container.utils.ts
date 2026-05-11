import {
  FAIL_FILTER_VALUE,
  includesMutedFindings,
  splitCsvFilterValues,
} from "@/lib/findings-filters";
import { FindingGroupRow } from "@/types";

export function isFailOnlyStatusFilter(
  filters: Record<string, string | string[] | undefined>,
): boolean {
  // Normalise both `filter[status]` and `filter[status__in]` CSV forms
  // and uppercase so "fail", "Fail" etc. still match the wire value.
  const direct = splitCsvFilterValues(filters["filter[status]"]).map((s) =>
    s.toUpperCase(),
  );
  if (direct.length > 0) {
    return direct.length === 1 && direct[0] === FAIL_FILTER_VALUE;
  }

  const multi = splitCsvFilterValues(filters["filter[status__in]"]).map((s) =>
    s.toUpperCase(),
  );
  return multi.length === 1 && multi[0] === FAIL_FILTER_VALUE;
}

export function getFilteredFindingGroupResourceCount(
  group: FindingGroupRow,
  filters: Record<string, string | string[] | undefined>,
): number {
  return isFailOnlyStatusFilter(filters)
    ? group.resourcesFail
    : group.resourcesTotal;
}

export function getFindingGroupSkeletonCount(
  group: FindingGroupRow,
  filters: Record<string, string | string[] | undefined>,
  maxSkeletonRows: number,
): number {
  const filteredTotal = getFilteredFindingGroupResourceCount(group, filters);

  // Reserve at least one row so the drill-down keeps visual space while the
  // empty state ("No resources found") replaces the skeleton.
  return Math.max(1, Math.min(filteredTotal, maxSkeletonRows));
}

export function getFindingGroupEmptyStateMessage(
  group: FindingGroupRow,
  filters: Record<string, string | string[] | undefined>,
): string {
  const hasFilters = Object.keys(filters).length > 0;

  if (!hasFilters) {
    return "No resources found.";
  }

  const mutedExcluded = !includesMutedFindings(filters);
  const hasMutedFindings = (group.mutedCount ?? 0) > 0;
  const visibleCount = getFilteredFindingGroupResourceCount(group, filters);

  if (mutedExcluded && hasMutedFindings && visibleCount === 0) {
    return "No resources match the current filters. Try enabling Include muted to view muted findings.";
  }

  return "No resources found for the selected filters.";
}
