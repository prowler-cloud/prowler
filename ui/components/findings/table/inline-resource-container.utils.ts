import { FindingGroupRow } from "@/types";

function parseStatusFilterValue(statusFilterValue?: string): string[] {
  if (!statusFilterValue) {
    return [];
  }

  return statusFilterValue
    .split(",")
    .map((status) => status.trim().toUpperCase())
    .filter(Boolean);
}

export function isFailOnlyStatusFilter(
  filters: Record<string, string | string[] | undefined>,
): boolean {
  const directStatusValues = parseStatusFilterValue(
    typeof filters["filter[status]"] === "string"
      ? filters["filter[status]"]
      : undefined,
  );

  if (directStatusValues.length > 0) {
    return directStatusValues.length === 1 && directStatusValues[0] === "FAIL";
  }

  const multiStatusValues = parseStatusFilterValue(
    typeof filters["filter[status__in]"] === "string"
      ? filters["filter[status__in]"]
      : undefined,
  );

  return multiStatusValues.length === 1 && multiStatusValues[0] === "FAIL";
}

function includesMutedFindings(
  filters: Record<string, string | string[] | undefined>,
): boolean {
  const mutedFilter = filters["filter[muted]"];

  if (Array.isArray(mutedFilter)) {
    return mutedFilter.includes("include");
  }

  return mutedFilter === "include";
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
