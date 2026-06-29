// Provisional UI/API contract fixtures only. API implementation is external to this
// UI slice; when the final API lands, update the adapter/server-action seam instead
// of teaching table or modal components about the transport payload shape.
const createFlatFindingWithTriageStatus = (status: string, index: number) => ({
  type: "findings",
  id: `finding-contract-${index}`,
  attributes: {
    uid: `prowler-finding-contract-uid-${index}`,
    status: "FAIL",
    triage_status: status,
    triage_has_note: false,
  },
});

export const allProvisionalTriageStatusFindings = [
  createFlatFindingWithTriageStatus("open", 1),
  createFlatFindingWithTriageStatus("under_review", 2),
  createFlatFindingWithTriageStatus("remediating", 3),
  createFlatFindingWithTriageStatus("resolved", 4),
  createFlatFindingWithTriageStatus("risk_accepted", 5),
  createFlatFindingWithTriageStatus("false_positive", 6),
  createFlatFindingWithTriageStatus("reopened", 7),
] as const;

export const flatFindingWithNotePresenceOnly = {
  type: "findings",
  id: "finding-note-presence-1",
  attributes: {
    uid: "prowler-finding-note-presence-uid-1",
    status: "FAIL",
    triage_id: "triage-note-presence-1",
    triage_status: "under_review",
    triage_notes_count: 1,
    triage_has_note: true,
  },
} as const;

export const flatFindingWithUnderReviewTriage = {
  type: "findings",
  id: "finding-1",
  attributes: {
    uid: "prowler-finding-uid-1",
    status: "FAIL",
    triage_id: "triage-note-presence-1",
    triage_status: "under_review",
    triage_notes_count: 1,
    triage_has_note: true,
  },
} as const;

export const flatPassFindingWithoutPersistedTriage = {
  type: "findings",
  id: "finding-pass-1",
  attributes: {
    uid: "prowler-finding-pass-uid-1",
    status: "PASS",
    triage_id: null,
    triage_status: null,
    triage_notes_count: 0,
    triage_has_note: false,
  },
} as const;

export const flatFindingWithAcceptedRiskTriage = {
  type: "findings",
  id: "finding-accepted-risk-1",
  attributes: {
    uid: "prowler-finding-accepted-risk-uid-1",
    status: "FAIL",
    triage_id: "triage-accepted-risk-1",
    triage_status: "risk_accepted",
    triage_notes_count: 1,
    triage_has_note: true,
    triage_note:
      "Accepted risk note body that must never appear in a table DTO.",
    source: "manual",
    updated_by: "user-1",
    inserted_at: "2026-06-01T10:00:00Z",
    updated_at: "2026-06-01T10:05:00Z",
  },
} as const;

export const findingTriageDetailResponse = {
  data: {
    type: "finding-triages",
    id: "triage-detail-1",
    attributes: {
      finding_id: "finding-1",
      finding_uid: "prowler-finding-uid-1",
      status: "risk_accepted",
      triage_notes_count: 1,
      has_note: true,
      note_id: "note-detail-1",
      current_note: "Current note visible only inside the modal.",
      source: "manual",
      updated_by: "user-1",
      inserted_at: "2026-06-03T10:00:00Z",
      updated_at: "2026-06-03T10:05:00Z",
    },
  },
} as const;
