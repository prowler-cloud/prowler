import { describe, expect, it } from "vitest";

import {
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_NOTE_PRIVACY_COPY,
  FINDING_TRIAGE_ORIGIN,
  FINDING_TRIAGE_STATUS,
  type FindingTriageDetail,
} from "@/types/findings-triage";

import { buildFindingTriageUpdateInput } from "./finding-triage-submit";

function makeTriageDetail(
  overrides?: Partial<FindingTriageDetail>,
): FindingTriageDetail {
  return {
    findingId: "finding-1",
    findingUid: "prowler-finding-uid-1",
    triageId: "triage-1",
    notesCount: 1,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: true,
    hasPersistedStatus: true,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    mutelistShortcutStatuses: [
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
    ],
    noteId: "note-1",
    noteBody: "Existing investigation note",
    maxNoteLength: FINDING_TRIAGE_NOTE_MAX_LENGTH,
    privacyCopy: FINDING_TRIAGE_NOTE_PRIVACY_COPY,
    ...overrides,
  };
}

describe("buildFindingTriageUpdateInput", () => {
  it("should return null when neither status nor note changed", () => {
    // Given
    const triage = makeTriageDetail();

    // When
    const result = buildFindingTriageUpdateInput({
      triage,
      selectedStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      noteBody: "Existing investigation note",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });

    // Then
    expect(result).toBeNull();
  });

  it("should update an existing note through noteId without duplicating note creation", () => {
    // Given
    const triage = makeTriageDetail();

    // When
    const result = buildFindingTriageUpdateInput({
      triage,
      selectedStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      noteBody: " Updated existing note ",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });

    // Then
    expect(result).toEqual({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      note: "Updated existing note",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });
  });

  it("should send status plus note only when creating the first note", () => {
    // Given
    const triage = makeTriageDetail({
      triageId: null,
      notesCount: 0,
      noteId: null,
      noteBody: "",
      hasVisibleNote: false,
    });

    // When
    const result = buildFindingTriageUpdateInput({
      triage,
      selectedStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      noteBody: " First note ",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });

    // Then
    expect(result).toEqual({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: null,
      notesCount: 0,
      noteId: null,
      status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      note: "First note",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });
  });

  it("should send only status when status changes and an existing note is unchanged", () => {
    // Given
    const triage = makeTriageDetail();

    // When
    const result = buildFindingTriageUpdateInput({
      triage,
      selectedStatus: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      noteBody: "Existing investigation note",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });

    // Then
    expect(result).toEqual({
      findingId: "finding-1",
      findingUid: "prowler-finding-uid-1",
      triageId: "triage-1",
      notesCount: 1,
      noteId: "note-1",
      status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });
  });

  it("should not update an existing note when the body is cleared", () => {
    // Given
    const triage = makeTriageDetail();

    // When
    const result = buildFindingTriageUpdateInput({
      triage,
      selectedStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      noteBody: "   ",
      origin: FINDING_TRIAGE_ORIGIN.MODAL,
    });

    // Then
    expect(result).toBeNull();
  });
});
