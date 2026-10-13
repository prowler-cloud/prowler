import { act, render } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  getStandaloneFindingColumnsMock,
  refreshMock,
  updateFindingTriageMock,
} = vi.hoisted(() => ({
  getStandaloneFindingColumnsMock: vi.fn(),
  refreshMock: vi.fn(),
  updateFindingTriageMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/actions/findings", () => ({
  loadFindingTriageDetail: vi.fn(),
  loadLatestFindingTriageNote: vi.fn(),
  updateFindingTriage: updateFindingTriageMock,
}));

vi.mock("@/components/findings/table/column-standalone-findings", () => ({
  getStandaloneFindingColumns: getStandaloneFindingColumnsMock,
}));

vi.mock("@/components/shadcn/table", () => ({
  DataTable: ({ header }: { header?: ReactNode }) => <div>{header}</div>,
}));

import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { LatestFindingsTable } from "./latest-findings-table";

describe("LatestFindingsTable", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getStandaloneFindingColumnsMock.mockReturnValue([]);
    updateFindingTriageMock.mockResolvedValue({ manualPassExpiresAt: null });
  });

  it("should refresh the full table after a manual pass update", async () => {
    // Given
    render(
      <LatestFindingsTable data={[]} header={<span>Latest findings</span>} />,
    );
    const onTriageUpdateAction = getStandaloneFindingColumnsMock.mock
      .calls[0][0].onTriageUpdateAction as (input: unknown) => Promise<unknown>;

    // When
    await act(() =>
      onTriageUpdateAction({
        findingId: "finding-1",
        findingUid: "finding-uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.RESOLVED,
        previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        manualPassEvidence: "Verified by the control owner.",
      }),
    );

    // Then
    expect(refreshMock).toHaveBeenCalledOnce();
  });
});
