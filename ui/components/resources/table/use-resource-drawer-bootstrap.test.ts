import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getResourceDrawerDataMock } = vi.hoisted(() => ({
  getResourceDrawerDataMock: vi.fn(),
}));

vi.mock("@/actions/resources", () => ({
  getResourceDrawerData: getResourceDrawerDataMock,
}));

import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageSummary,
} from "@/types/findings-triage";

import type { ResourceFinding } from "./resource-findings-columns";
import { useResourceDrawerBootstrap } from "./use-resource-drawer-bootstrap";

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

function makeFinding(overrides?: Partial<ResourceFinding>): ResourceFinding {
  return {
    type: "findings",
    id: "finding-1",
    triage: makeTriageSummary(),
    attributes: {
      status: "FAIL",
      severity: "critical",
      muted: false,
      muted_reason: undefined,
      updated_at: "2026-03-30T10:05:00Z",
      check_metadata: {
        checktitle: "S3 public access",
      },
    },
    ...overrides,
  };
}

function renderBootstrap(findingsReloadNonce = 0) {
  return renderHook(() =>
    useResourceDrawerBootstrap({
      resourceId: "resource-1",
      resourceUid: "resource-uid-1",
      providerId: "provider-1",
      providerType: "aws",
      currentPage: 1,
      pageSize: 10,
      searchQuery: "",
      findingsReloadNonce,
    }),
  );
}

describe("useResourceDrawerBootstrap", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getResourceDrawerDataMock.mockResolvedValue({
      findings: [makeFinding()],
      findingsMeta: null,
      providerOrg: null,
      resourceTags: {},
    });
  });

  it("should patch finding triage locally without reloading drawer data", async () => {
    // Given
    const { result } = renderBootstrap();

    await waitFor(() => expect(result.current.findingsLoading).toBe(false));
    const loadCount = getResourceDrawerDataMock.mock.calls.length;

    // When
    act(() => {
      result.current.patchTriageUpdate({
        findingId: "finding-1",
        findingUid: "uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        previousStatus: FINDING_TRIAGE_STATUS.UNDER_REVIEW,
        isMuted: false,
        note: "Investigating",
      });
    });

    // Then
    expect(result.current.findingsData[0]?.triage).toEqual(
      expect.objectContaining({
        status: FINDING_TRIAGE_STATUS.REMEDIATING,
        label: "Remediating",
        hasVisibleNote: true,
        notesCount: 1,
      }),
    );
    expect(getResourceDrawerDataMock).toHaveBeenCalledTimes(loadCount);
  });
});
