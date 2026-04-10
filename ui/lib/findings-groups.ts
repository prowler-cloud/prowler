import type { FindingGroupRow } from "@/types";

type FindingGroupMutedState = Pick<
  FindingGroupRow,
  "muted" | "mutedCount" | "resourcesFail" | "resourcesTotal"
>;

type FindingGroupDeltaState = Pick<
  FindingGroupRow,
  | "newCount"
  | "changedCount"
  | "newFailCount"
  | "newFailMutedCount"
  | "newPassCount"
  | "newPassMutedCount"
  | "newManualCount"
  | "newManualMutedCount"
  | "changedFailCount"
  | "changedFailMutedCount"
  | "changedPassCount"
  | "changedPassMutedCount"
  | "changedManualCount"
  | "changedManualMutedCount"
>;

export function isFindingGroupMuted(group: FindingGroupMutedState): boolean {
  if (typeof group.muted === "boolean") {
    return group.muted;
  }

  const mutedCount = group.mutedCount ?? 0;
  if (mutedCount === 0) {
    return false;
  }

  return (
    mutedCount === group.resourcesFail || mutedCount === group.resourcesTotal
  );
}

function getNewDeltaTotal(group: FindingGroupDeltaState): number {
  const breakdownTotal =
    (group.newFailCount ?? 0) +
    (group.newFailMutedCount ?? 0) +
    (group.newPassCount ?? 0) +
    (group.newPassMutedCount ?? 0) +
    (group.newManualCount ?? 0) +
    (group.newManualMutedCount ?? 0);

  return breakdownTotal > 0 ? breakdownTotal : group.newCount;
}

function getChangedDeltaTotal(group: FindingGroupDeltaState): number {
  const breakdownTotal =
    (group.changedFailCount ?? 0) +
    (group.changedFailMutedCount ?? 0) +
    (group.changedPassCount ?? 0) +
    (group.changedPassMutedCount ?? 0) +
    (group.changedManualCount ?? 0) +
    (group.changedManualMutedCount ?? 0);

  return breakdownTotal > 0 ? breakdownTotal : group.changedCount;
}

export function getFindingGroupDelta(
  group: FindingGroupDeltaState,
): "new" | "changed" | "none" {
  if (getNewDeltaTotal(group) > 0) {
    return "new";
  }

  if (getChangedDeltaTotal(group) > 0) {
    return "changed";
  }

  return "none";
}

const FINDING_GROUP_STATUSES = ["FAIL", "PASS", "MANUAL"] as const;
type FindingGroupStatus = (typeof FINDING_GROUP_STATUSES)[number];

type FindingGroupFiltersRecord = Record<string, string | string[] | undefined>;

function parseStatusFilterValue(
  rawValue: string | string[] | undefined,
): FindingGroupStatus[] {
  if (!rawValue) {
    return [];
  }

  const joined = Array.isArray(rawValue) ? rawValue.join(",") : rawValue;

  return joined
    .split(",")
    .map((status) => status.trim().toUpperCase())
    .filter((status): status is FindingGroupStatus =>
      (FINDING_GROUP_STATUSES as readonly string[]).includes(status),
    );
}

/**
 * Returns the set of statuses the user has explicitly narrowed the findings
 * view to, or null when no status filter is active (→ all statuses should be
 * considered). Supports both `filter[status]` (single value) and
 * `filter[status__in]` (comma-separated values).
 */
export function getActiveStatusFilter(
  filters: FindingGroupFiltersRecord,
): Set<FindingGroupStatus> | null {
  const direct = parseStatusFilterValue(filters["filter[status]"]);
  if (direct.length > 0) {
    return new Set(direct);
  }

  const multi = parseStatusFilterValue(filters["filter[status__in]"]);
  if (multi.length > 0) {
    return new Set(multi);
  }

  return null;
}

function hasAnyDeltaBreakdown(group: FindingGroupDeltaState): boolean {
  return (
    (group.newFailCount ?? 0) > 0 ||
    (group.newFailMutedCount ?? 0) > 0 ||
    (group.newPassCount ?? 0) > 0 ||
    (group.newPassMutedCount ?? 0) > 0 ||
    (group.newManualCount ?? 0) > 0 ||
    (group.newManualMutedCount ?? 0) > 0 ||
    (group.changedFailCount ?? 0) > 0 ||
    (group.changedFailMutedCount ?? 0) > 0 ||
    (group.changedPassCount ?? 0) > 0 ||
    (group.changedPassMutedCount ?? 0) > 0 ||
    (group.changedManualCount ?? 0) > 0 ||
    (group.changedManualMutedCount ?? 0) > 0
  );
}

function getNewDeltaForStatuses(
  group: FindingGroupDeltaState,
  statuses: Set<FindingGroupStatus>,
): number {
  let total = 0;
  if (statuses.has("FAIL")) {
    total += (group.newFailCount ?? 0) + (group.newFailMutedCount ?? 0);
  }
  if (statuses.has("PASS")) {
    total += (group.newPassCount ?? 0) + (group.newPassMutedCount ?? 0);
  }
  if (statuses.has("MANUAL")) {
    total += (group.newManualCount ?? 0) + (group.newManualMutedCount ?? 0);
  }
  return total;
}

function getChangedDeltaForStatuses(
  group: FindingGroupDeltaState,
  statuses: Set<FindingGroupStatus>,
): number {
  let total = 0;
  if (statuses.has("FAIL")) {
    total += (group.changedFailCount ?? 0) + (group.changedFailMutedCount ?? 0);
  }
  if (statuses.has("PASS")) {
    total += (group.changedPassCount ?? 0) + (group.changedPassMutedCount ?? 0);
  }
  if (statuses.has("MANUAL")) {
    total +=
      (group.changedManualCount ?? 0) + (group.changedManualMutedCount ?? 0);
  }
  return total;
}

/**
 * Filter-aware variant of {@link getFindingGroupDelta}. When a status filter
 * is active, only delta counters belonging to the filtered statuses contribute
 * to the indicator. When no status filter is active, or when the API response
 * lacks breakdown counters (legacy shape), this falls back to the aggregate
 * delta so rows still surface deltas correctly.
 */
export function getFilteredFindingGroupDelta(
  group: FindingGroupDeltaState,
  filters: FindingGroupFiltersRecord,
): "new" | "changed" | "none" {
  const activeStatuses = getActiveStatusFilter(filters);

  if (!activeStatuses || !hasAnyDeltaBreakdown(group)) {
    return getFindingGroupDelta(group);
  }

  if (getNewDeltaForStatuses(group, activeStatuses) > 0) {
    return "new";
  }

  if (getChangedDeltaForStatuses(group, activeStatuses) > 0) {
    return "changed";
  }

  return "none";
}
