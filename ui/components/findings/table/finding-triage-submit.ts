import {
  type FindingTriageDetail,
  type FindingTriageManualStatus,
  type FindingTriageStatus,
  isManualStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

export interface BuildFindingTriageUpdateInputParams {
  triage: FindingTriageDetail;
  selectedStatus: FindingTriageStatus;
  noteBody: string;
}

export function buildFindingTriageUpdateInput({
  triage,
  selectedStatus,
  noteBody,
}: BuildFindingTriageUpdateInputParams): UpdateFindingTriageInput | null {
  const trimmedNote = noteBody.trim();
  const statusChanged = selectedStatus !== triage.status;
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
