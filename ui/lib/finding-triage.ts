import {
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageSummary,
  isMutelistShortcutStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

export const shouldMarkFindingMutedForTriageUpdate = (
  input: UpdateFindingTriageInput,
): boolean => Boolean(input.status && isMutelistShortcutStatus(input.status));

export const shouldRefreshAfterTriageUpdate = (
  input: UpdateFindingTriageInput,
): boolean =>
  shouldMarkFindingMutedForTriageUpdate(input) && input.isMuted !== true;

export const getOptimisticTriageMutedReason = (
  status: NonNullable<UpdateFindingTriageInput["status"]>,
): string =>
  `Finding triage status changed to ${FINDING_TRIAGE_STATUS_LABELS[status]}.`;

export const applyOptimisticTriageSummaryUpdate = (
  triage: FindingTriageSummary,
  input: UpdateFindingTriageInput,
): FindingTriageSummary => {
  const noteWasUpdated = Object.prototype.hasOwnProperty.call(input, "note");
  const noteHasContent =
    typeof input.note === "string" && input.note.length > 0;
  const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(input);

  return {
    ...triage,
    ...(input.status
      ? {
          status: input.status,
          label: FINDING_TRIAGE_STATUS_LABELS[input.status],
          isMuted: shouldMarkMuted ? true : triage.isMuted,
        }
      : {}),
    ...(noteWasUpdated
      ? {
          hasVisibleNote: noteHasContent,
          notesCount: noteHasContent ? Math.max(triage.notesCount, 1) : 0,
        }
      : {}),
  };
};
