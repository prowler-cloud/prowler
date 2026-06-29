import {
  type FindingTriageDetail,
  type FindingTriageManualStatus,
  type FindingTriageOrigin,
  type FindingTriageStatus,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import { isManualStatus } from "./finding-triage-status-control";

export interface BuildFindingTriageUpdateInputParams {
  triage: FindingTriageDetail;
  selectedStatus: FindingTriageStatus;
  noteBody: string;
  origin: FindingTriageOrigin;
}

export function buildFindingTriageUpdateInput({
  triage,
  selectedStatus,
  noteBody,
  origin,
}: BuildFindingTriageUpdateInputParams): UpdateFindingTriageInput | null {
  const trimmedNote = noteBody.trim();
  const statusChanged = selectedStatus !== triage.status;
  const shouldCreateFirstNote =
    triage.notesCount === 0 && trimmedNote.length > 0;
  const shouldUpdateExistingNote =
    triage.notesCount > 0 &&
    triage.noteId !== null &&
    trimmedNote.length > 0 &&
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
    ...(shouldIncludeStatus
      ? { status: selectedStatus as FindingTriageManualStatus }
      : {}),
    ...(shouldCreateFirstNote || shouldUpdateExistingNote
      ? { note: trimmedNote }
      : {}),
    origin,
  };
}
