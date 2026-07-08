import { isFindingGroupMuted } from "@/lib/findings-groups";

interface FindingGroupSelectionState {
  resourcesFail: number;
  resourcesTotal?: number;
  muted?: boolean;
  mutedCount?: number;
}

export function canMuteFindingGroup({
  resourcesFail,
  muted,
  mutedCount,
  resourcesTotal,
}: FindingGroupSelectionState): boolean {
  return (
    resourcesFail > 0 &&
    !isFindingGroupMuted({
      muted,
      mutedCount: mutedCount ?? 0,
      resourcesFail,
      resourcesTotal: resourcesTotal ?? 0,
    })
  );
}
