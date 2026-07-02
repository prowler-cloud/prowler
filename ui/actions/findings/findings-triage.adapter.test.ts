import { describe, expect, it } from "vitest";

import {
  FINDING_TRIAGE_DISABLED_REASON,
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
} from "@/types/findings-triage";

import {
  adaptFindingTriageDetailResponse,
  adaptFindingTriageSummariesResponse,
  adaptLatestFindingTriageNote,
  attachFindingTriageSummariesToResponse,
} from "./findings-triage.adapter";
import {
  allProvisionalTriageStatusFindings,
  findingTriageDetailResponse,
  flatFindingWithAcceptedRiskTriage,
  flatFindingWithNotePresenceOnly,
  flatFindingWithUnderReviewTriage,
  flatPassFindingWithoutPersistedTriage,
} from "./findings-triage.fixtures";

const expectNoRawTransportKeys = (value: Record<string, unknown>) => {
  expect(value).not.toHaveProperty("attributes");
  expect(value).not.toHaveProperty("relationships");
  expect(value).not.toHaveProperty("included");
  expect(value).not.toHaveProperty("triage_status");
  expect(value).not.toHaveProperty("triage_has_note");
  expect(value).not.toHaveProperty("triage_note");
  expect(value).not.toHaveProperty("current_note");
  expect(value).not.toHaveProperty("source");
  expect(value).not.toHaveProperty("updated_by");
  expect(value).not.toHaveProperty("inserted_at");
  expect(value).not.toHaveProperty("updated_at");
};

describe("provisional findings triage contract fixtures", () => {
  it("should document every triage status the provisional contract can return", () => {
    // Given
    const input = {
      data: allProvisionalTriageStatusFindings,
    };

    // When
    const result = adaptFindingTriageSummariesResponse(input, {
      canEdit: true,
    });

    // Then
    expect(result).toHaveLength(7);
    expect(result.map((summary) => summary.status)).toEqual([
      FINDING_TRIAGE_STATUS.OPEN,
      FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      FINDING_TRIAGE_STATUS.REMEDIATING,
      FINDING_TRIAGE_STATUS.RESOLVED,
      FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
      FINDING_TRIAGE_STATUS.REOPENED,
    ]);
    expect(result.map((summary) => summary.label)).toEqual([
      "Open",
      "Under Review",
      "Remediating",
      "Resolved",
      "Risk Accepted",
      "False Positive",
      "Reopened",
    ]);
    expect(result[0].label).toBe(
      FINDING_TRIAGE_STATUS_LABELS[FINDING_TRIAGE_STATUS.OPEN],
    );
  });

  it("should model table note presence without requiring note previews", () => {
    // Given
    const input = {
      data: [flatFindingWithNotePresenceOnly],
    };

    // When
    const [summary] = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(summary).toEqual(
      expect.objectContaining({
        findingId: "finding-note-presence-1",
        findingUid: "prowler-finding-note-presence-uid-1",
        hasVisibleNote: true,
      }),
    );
    expect(JSON.stringify(summary)).not.toContain("triage_note");
    expect(JSON.stringify(summary)).not.toContain("current_note");
  });

  it("should model modal note detail as a separate detail payload", () => {
    // Given / When
    const detail = adaptFindingTriageDetailResponse(
      findingTriageDetailResponse,
    );

    // Then
    expect(detail.noteBody).toBe("Current note visible only inside the modal.");
    expect(detail.hasVisibleNote).toBe(true);
    expect(detail.maxNoteLength).toBe(500);
  });

  it("should model disabled non-paying state through adapter options only", () => {
    // Given
    const input = {
      data: [flatFindingWithUnderReviewTriage],
    };

    // When
    const [summary] = adaptFindingTriageSummariesResponse(input, {
      canEdit: false,
      disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
    });

    // Then
    expect(summary.canEdit).toBe(false);
    expect(summary.disabledReason).toBe(
      FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY,
    );
    expect(summary.billingHref).toBe("https://prowler.com/pricing");
  });
});

describe("adaptLatestFindingTriageNote", () => {
  it("should adapt the newest note from a JSON:API collection", () => {
    // Given
    const response = {
      data: [
        {
          id: "note-latest",
          type: "finding-triage-notes",
          attributes: {
            body: "Latest investigation note",
          },
        },
      ],
    };

    // When
    const result = adaptLatestFindingTriageNote(response);

    // Then
    expect(result).toEqual({
      noteId: "note-latest",
      noteBody: "Latest investigation note",
    });
  });

  it("should return null when the response has no usable note", () => {
    expect(adaptLatestFindingTriageNote({ data: [] })).toBeNull();
    expect(
      adaptLatestFindingTriageNote({ data: [{ id: "note-1" }] }),
    ).toBeNull();
  });
});

describe("adaptFindingTriageSummariesResponse", () => {
  it("should return [] when the provisional API response is malformed", () => {
    // Given
    const input = { meta: { count: 0 } };

    // When
    const result = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(result).toEqual([]);
  });

  it("should skip malformed entries inside a data array", () => {
    // Given
    const input = {
      data: [null, "bad-entry", flatFindingWithUnderReviewTriage],
    };

    // When
    const result = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(
      expect.objectContaining({
        findingId: "finding-1",
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      }),
    );
  });

  it("should not shift attached summaries after malformed entries", () => {
    // Given
    const validWithoutTriage = {
      id: "resource-row-1",
      type: "finding-group-resources",
      attributes: {
        finding_id: "finding-1",
        finding_uid: "prowler-finding-uid-1",
        triage_status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        triage_notes_count: 1,
        status: "FAIL",
      },
    };
    const laterValidWithoutTriage = {
      id: "resource-row-2",
      type: "finding-group-resources",
      attributes: {
        finding_id: "finding-2",
        finding_uid: "prowler-finding-uid-2",
        triage_status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        triage_notes_count: 0,
        status: "MUTED",
      },
    };
    const input = {
      data: [validWithoutTriage, null, laterValidWithoutTriage],
    };

    // When
    const result = attachFindingTriageSummariesToResponse(input);

    // Then
    expect(result?.data[0]).toEqual(
      expect.objectContaining({
        triage: expect.objectContaining({
          findingId: "finding-1",
          status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        }),
      }),
    );
    expect(result?.data[1]).toBeNull();
    expect(result?.data[2]).toEqual(
      expect.objectContaining({
        triage: expect.objectContaining({
          findingId: "finding-2",
          status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        }),
      }),
    );
  });

  it("should use triage_notes_count from the resource triage API contract", () => {
    // Given
    const input = {
      data: [
        {
          id: "resource-row-1",
          type: "finding-group-resources",
          attributes: {
            finding_id: "finding-1",
            finding_uid: "prowler-finding-uid-1",
            triage_status: FINDING_TRIAGE_STATUS.REMEDIATING,
            triage_notes_count: 5,
            status: "FAIL",
          },
        },
        {
          id: "resource-row-2",
          type: "finding-group-resources",
          attributes: {
            finding_id: "finding-2",
            finding_uid: "prowler-finding-uid-2",
            triage_status: FINDING_TRIAGE_STATUS.OPEN,
            triage_notes_count: 0,
            status: "FAIL",
          },
        },
      ],
    };

    // When
    const result = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual(
      expect.objectContaining({
        hasVisibleNote: true,
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
      }),
    );
    expect(result[1]).toEqual(
      expect.objectContaining({
        hasVisibleNote: false,
        status: FINDING_TRIAGE_STATUS.OPEN,
      }),
    );
  });

  it("should mark triage as muted when resource status is MUTED", () => {
    // Given
    const input = {
      data: [
        {
          id: "resource-row-muted-1",
          type: "finding-group-resources",
          attributes: {
            finding_id: "finding-muted-1",
            finding_uid: "prowler-finding-muted-uid-1",
            triage_status: FINDING_TRIAGE_STATUS.OPEN,
            triage_notes_count: 0,
            status: "MUTED",
          },
        },
      ],
    };

    // When
    const [summary] = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(summary).toEqual(
      expect.objectContaining({
        findingId: "finding-muted-1",
        isMuted: true,
        status: FINDING_TRIAGE_STATUS.OPEN,
      }),
    );
  });

  it("should normalize flat provisional finding fields into domain triage summaries", () => {
    // Given
    const input = {
      data: [flatFindingWithUnderReviewTriage],
    };

    // When
    const result = adaptFindingTriageSummariesResponse(input, {
      canEdit: true,
    });

    // Then
    expect(result).toEqual([
      expect.objectContaining({
        findingId: "finding-1",
        findingUid: "prowler-finding-uid-1",
        status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        label: "Under Review",
        hasVisibleNote: true,
        canEdit: true,
        billingHref: "https://prowler.com/pricing",
      }),
    ]);
  });

  it("should fallback from scan status when no persisted triage status exists", () => {
    // Given
    const input = {
      data: [flatPassFindingWithoutPersistedTriage],
    };

    // When
    const result = adaptFindingTriageSummariesResponse(input);

    // Then
    expect(result[0]).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.RESOLVED,
        label: "Resolved",
        hasVisibleNote: false,
      }),
    );
  });

  it("should keep raw provisional fields out of table component DTOs", () => {
    // Given
    const input = {
      data: [flatFindingWithAcceptedRiskTriage],
    };

    // When
    const [summary] = adaptFindingTriageSummariesResponse(input);

    // Then
    expectNoRawTransportKeys(summary as unknown as Record<string, unknown>);
    expect(JSON.stringify(summary)).not.toContain("Accepted risk note body");
  });
});

describe("adaptFindingTriageDetailResponse", () => {
  it("should normalize provisional detail payloads into modal DTOs", () => {
    // Given
    const input = findingTriageDetailResponse;

    // When
    const detail = adaptFindingTriageDetailResponse(input, {
      canEdit: true,
    });

    // Then
    expect(detail).toEqual(
      expect.objectContaining({
        findingId: "finding-1",
        findingUid: "prowler-finding-uid-1",
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        label: "Risk Accepted",
        hasVisibleNote: true,
        canEdit: true,
        noteBody: "Current note visible only inside the modal.",
        maxNoteLength: 500,
      }),
    );
  });

  it("should keep raw provisional fields out of modal component DTOs", () => {
    // Given
    const input = findingTriageDetailResponse;

    // When
    const detail = adaptFindingTriageDetailResponse(input);

    // Then
    expectNoRawTransportKeys(detail as unknown as Record<string, unknown>);
  });
});
