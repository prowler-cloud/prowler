import {
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageSummary,
  isMutelistShortcutStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

interface FindingTriageRowAttributes {
  muted?: boolean;
  muted_reason?: string;
}

export interface FindingTriageRow {
  triage?: FindingTriageSummary;
  attributes: FindingTriageRowAttributes;
}

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

export const applyOptimisticFindingTriageRowUpdate = <
  TRow extends FindingTriageRow,
>(
  finding: TRow,
  input: UpdateFindingTriageInput,
): TRow => {
  if (!finding.triage || finding.triage.findingId !== input.findingId) {
    return finding;
  }

  const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(input);

  return {
    ...finding,
    triage: applyOptimisticTriageSummaryUpdate(finding.triage, input),
    attributes: {
      ...finding.attributes,
      muted: shouldMarkMuted ? true : finding.attributes.muted,
      muted_reason:
        shouldMarkMuted && input.isMuted !== true && input.status
          ? getOptimisticTriageMutedReason(input.status)
          : finding.attributes.muted_reason,
    },
  };
};

export const applyOptimisticFindingTriageRowsUpdate = <
  TRow extends FindingTriageRow,
>(
  findings: TRow[],
  input: UpdateFindingTriageInput,
): TRow[] =>
  findings.map((finding) =>
    applyOptimisticFindingTriageRowUpdate(finding, input),
  );
