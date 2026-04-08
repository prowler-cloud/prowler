interface FindingGroupSelectionState {
  resourcesFail: number;
  resourcesTotal: number;
  mutedCount: number;
}

export function canMuteFindingGroup({
  resourcesFail,
  mutedCount,
}: FindingGroupSelectionState): boolean {
  const allMuted = mutedCount > 0 && mutedCount === resourcesFail;
  return resourcesFail > 0 && !allMuted;
}
