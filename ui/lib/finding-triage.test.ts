import { describe, expect, it } from "vitest";

import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import {
  applyOptimisticFindingTriageRowsUpdate,
  applyOptimisticFindingTriageRowUpdate,
} from "./finding-triage";

interface TestFindingRowAttributes {
  muted: boolean;
  muted_reason?: string;
  status: string;
}

interface TestFindingRow {
  id: string;
  triage?: FindingTriageSummary;
  attributes: TestFindingRowAttributes;
}

function makeTriageSummary(
  overrides?: Partial<FindingTriageSummary>,
): FindingTriageSummary {
  return {
    findingId: "finding-1",
    findingUid: "uid-1",
    triageId: "triage-1",
    notesCount: 0,
    status: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
    label: "Under Review",
    hasVisibleNote: false,
    isMuted: false,
    canEdit: true,
    billingHref: "https://prowler.com/pricing",
    ...overrides,
  };
}

function makeFindingRow(overrides?: Partial<TestFindingRow>): TestFindingRow {
  return {
    id: "finding-1",
    triage: makeTriageSummary(),
    attributes: {
      muted: false,
      muted_reason: undefined,
      status: "FAIL",
    },
    ...overrides,
  };
}

describe("finding triage optimistic row updates", () => {
  it("should patch matching finding row triage and muted attributes", () => {
    // Given
    const finding = makeFindingRow();

    // When
    const result = applyOptimisticFindingTriageRowUpdate(finding, {
      findingId: "finding-1",
      findingUid: "uid-1",
      triageId: "triage-1",
      notesCount: 0,
      status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
      previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
      isMuted: false,
      note: "Accepted by owner.",
    });

    // Then
    expect(result).not.toBe(finding);
    expect(result.triage).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
        label: "Risk Accepted",
        hasVisibleNote: true,
        notesCount: 1,
        isMuted: true,
      }),
    );
    expect(result.attributes).toEqual(
      expect.objectContaining({
        muted: true,
        muted_reason: "Finding triage status changed to Risk Accepted.",
        status: "FAIL",
      }),
    );
  });

  it("should leave non-matching rows unchanged when patching a list", () => {
    // Given
    const matchingFinding = makeFindingRow();
    const otherFinding = makeFindingRow({
      id: "finding-2",
      triage: makeTriageSummary({
        findingId: "finding-2",
        findingUid: "uid-2",
        triageId: "triage-2",
      }),
    });

    // When
    const result = applyOptimisticFindingTriageRowsUpdate(
      [matchingFinding, otherFinding],
      {
        findingId: "finding-1",
        findingUid: "uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        isMuted: false,
      },
    );

    // Then
    expect(result[0]?.triage).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
      }),
    );
    expect(result[1]).toBe(otherFinding);
  });

  it("should leave rows without triage unchanged", () => {
    // Given
    const finding = makeFindingRow({ triage: undefined });

    // When
    const result = applyOptimisticFindingTriageRowUpdate(finding, {
      findingId: "finding-1",
      findingUid: "uid-1",
      triageId: null,
      notesCount: 0,
      note: "No triage payload on this row.",
      isMuted: false,
    });

    // Then
    expect(result).toBe(finding);
  });
});
