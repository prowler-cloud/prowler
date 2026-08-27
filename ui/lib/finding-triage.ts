import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_STATUS_LABELS,
  FINDING_TRIAGE_STATUS,
  MANUAL_PASS_PROVENANCE,
  type FindingTriageSummary,
  isMutelistShortcutStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

interface FindingTriageRowAttributes {
  muted?: boolean;
  muted_reason?: string;
  status?: string;
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

export const isManualPassTriageUpdate = (
  input: UpdateFindingTriageInput,
): boolean =>
  input.status === FINDING_TRIAGE_STATUS.RESOLVED &&
  Boolean(input.manualPassEvidence);

export const applyOptimisticTriageSummaryUpdate = (
  triage: FindingTriageSummary,
  input: UpdateFindingTriageInput,
): FindingTriageSummary => {
  const manualPassHasEvidence = Boolean(input.manualPassEvidence?.trim());
  const noteWasUpdated =
    Object.prototype.hasOwnProperty.call(input, "note") ||
    manualPassHasEvidence;
  const noteHasContent =
    (typeof input.note === "string" && input.note.length > 0) ||
    manualPassHasEvidence;
  const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(input);
  return {
    ...triage,
    ...(input.status
      ? {
          status: input.status,
          label: FINDING_TRIAGE_STATUS_LABELS[input.status],
          manualPassProvenance: input.manualPassEvidence
            ? MANUAL_PASS_PROVENANCE
            : triage.manualPassProvenance,
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
  const isManualPass = isManualPassTriageUpdate(input);

  return {
    ...finding,
    triage: applyOptimisticTriageSummaryUpdate(finding.triage, input),
    attributes: {
      ...finding.attributes,
      status: isManualPass ? FINDING_STATUS.PASS : finding.attributes.status,
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
