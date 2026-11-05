import { FINDING_STATUS } from "@/types/components";
import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
  type FindingTriageManualStatus,
  type FindingTriageModalStatus,
  isManualStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

export interface BuildFindingTriageUpdateInputParams {
  triage: FindingTriageDetail;
  selectedStatus: FindingTriageModalStatus;
  noteBody: string;
  manualPassEvidence?: string;
}

export function buildFindingTriageUpdateInput({
  triage,
  selectedStatus,
  noteBody,
  manualPassEvidence = "",
}: BuildFindingTriageUpdateInputParams): UpdateFindingTriageInput | null {
  const trimmedNote = noteBody.trim();
  const trimmedManualPassEvidence = manualPassEvidence.trim();
  const statusChanged = selectedStatus !== triage.status;

  if (
    selectedStatus === FINDING_TRIAGE_STATUS.RESOLVED &&
    selectedStatus !== triage.status
  ) {
    if (
      triage.rawFindingStatus !== FINDING_STATUS.MANUAL ||
      !isManualStatus(triage.status) ||
      trimmedManualPassEvidence.length === 0
    ) {
      return null;
    }

    return {
      findingId: triage.findingId,
      findingUid: triage.findingUid,
      triageId: triage.triageId,
      notesCount: triage.notesCount,
      noteId: triage.noteId,
      isMuted: triage.isMuted,
      status: FINDING_TRIAGE_STATUS.RESOLVED,
      previousStatus: triage.status,
      manualPassEvidence: trimmedManualPassEvidence,
    };
  }
  const shouldCreateFirstNote =
    triage.notesCount === 0 && trimmedNote.length > 0;
  const shouldUpdateExistingNote =
    triage.notesCount > 0 &&
    triage.noteId !== null &&
    trimmedNote !== triage.noteBody;
  const shouldIncludeStatus =
    isManualStatus(selectedStatus) && (statusChanged || shouldCreateFirstNote);

  if (
    !shouldIncludeStatus &&
    !shouldCreateFirstNote &&
    !shouldUpdateExistingNote
  ) {
    return null;
  }

  return {
    findingId: triage.findingId,
    findingUid: triage.findingUid,
    triageId: triage.triageId,
    notesCount: triage.notesCount,
    noteId: triage.noteId,
    isMuted: triage.isMuted,
    ...(shouldIncludeStatus
      ? {
          status: selectedStatus as FindingTriageManualStatus,
          previousStatus: triage.status,
        }
      : {}),
    ...(shouldCreateFirstNote || shouldUpdateExistingNote
      ? { note: trimmedNote }
      : {}),
  };
}
