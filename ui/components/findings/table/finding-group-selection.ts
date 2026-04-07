interface FindingGroupSelectionState {
  resourcesFail: number;
  resourcesTotal: number;
  mutedCount: number;
}

export function canMuteFindingGroup({
  resourcesFail,
  resourcesTotal,
  mutedCount,
}: FindingGroupSelectionState): boolean {
  const allMuted = mutedCount > 0 && mutedCount === resourcesTotal;
  return resourcesFail > 0 && !allMuted;
}
