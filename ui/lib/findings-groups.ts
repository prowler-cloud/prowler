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
