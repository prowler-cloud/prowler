import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { useFindingGroupResourcesMock, useResourceDetailDrawerMock } =
  vi.hoisted(() => ({
    useFindingGroupResourcesMock: vi.fn(),
    useResourceDetailDrawerMock: vi.fn(),
  }));

vi.mock("@/hooks/use-finding-group-resources", () => ({
  useFindingGroupResources: useFindingGroupResourcesMock,
}));

vi.mock("@/lib", () => ({
  applyDefaultMutedFilter: (
    filters: Record<string, string | string[] | undefined>,
  ) => ({
    "filter[muted]": "false",
    ...filters,
  }),
}));

vi.mock("@/components/findings/table/resource-detail-drawer", () => ({
  useResourceDetailDrawer: useResourceDetailDrawerMock,
}));

import {
  type FindingGroupRow,
  type FindingResourceRow,
  FINDINGS_ROW_TYPE,
} from "@/types";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

import { useFindingGroupResourceState } from "./use-finding-group-resource-state";

const group: FindingGroupRow = {
  id: "group-1",
  rowType: FINDINGS_ROW_TYPE.GROUP,
  checkId: "s3_bucket_public_access",
  checkTitle: "S3 Bucket Public Access",
  severity: "high",
  status: "FAIL",
  resourcesTotal: 3,
  resourcesFail: 2,
  newCount: 1,
  changedCount: 0,
  mutedCount: 0,
  providers: ["aws"],
  updatedAt: "2026-04-22T10:00:00Z",
};

describe("useFindingGroupResourceState", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useFindingGroupResourcesMock.mockReturnValue({
      sentinelRef: vi.fn(),
      refresh: vi.fn(),
      loadMore: vi.fn(),
      totalCount: 3,
    });

    useResourceDetailDrawerMock.mockReturnValue({
      isOpen: false,
      isLoading: false,
      isNavigating: false,
      checkMeta: null,
      currentIndex: 0,
      totalResources: 3,
      currentResource: null,
      currentFinding: null,
      otherFindings: [],
      openDrawer: vi.fn(),
      closeDrawer: vi.fn(),
      navigatePrev: vi.fn(),
      navigateNext: vi.fn(),
      refetchCurrent: vi.fn(),
    });
  });

  it("applies the shared default muted filter when the user has not opted in", () => {
    renderHook(() =>
      useFindingGroupResourceState({
        group,
        filters: {
          "filter[provider_type__in]": "aws",
        },
        hasHistoricalData: false,
      }),
    );

    expect(useFindingGroupResourcesMock).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: {
          "filter[provider_type__in]": "aws",
          "filter[muted]": "false",
        },
      }),
    );
    expect(useResourceDetailDrawerMock).toHaveBeenCalledWith(
      expect.objectContaining({
        includeMutedInOtherFindings: false,
      }),
    );
  });

  it("includes muted findings in the drawer only when filter[muted]=include is active", () => {
    renderHook(() =>
      useFindingGroupResourceState({
        group,
        filters: {
          "filter[muted]": "include",
        },
        hasHistoricalData: false,
      }),
    );

    expect(useFindingGroupResourcesMock).toHaveBeenCalledWith(
      expect.objectContaining({
        filters: {
          "filter[muted]": "include",
        },
      }),
    );
    expect(useResourceDetailDrawerMock).toHaveBeenCalledWith(
      expect.objectContaining({
        includeMutedInOtherFindings: true,
      }),
    );
  });

  it("preserves an existing mute reason for already-muted optimistic shortcut updates", async () => {
    // Given
    const mutedResource: FindingResourceRow = {
      id: "resource-1",
      rowType: FINDINGS_ROW_TYPE.RESOURCE,
      findingId: "finding-1",
      checkId: "check-1",
      providerType: "aws",
      providerAlias: "production",
      providerUid: "provider-1",
      resourceName: "resource-1",
      resourceType: "Bucket",
      resourceGroup: "default",
      resourceUid: "resource-uid-1",
      service: "s3",
      region: "us-east-1",
      severity: "high",
      status: "MUTED",
      statusExtended: "Muted finding",
      delta: null,
      isMuted: true,
      mutedReason: "Existing mute rule",
      firstSeenAt: null,
      lastSeenAt: "2026-04-22T10:00:00Z",
      triage: {
        findingId: "finding-1",
        findingUid: "finding-uid-1",
        triageId: "triage-1",
        notesCount: 0,
        status: FINDING_TRIAGE_STATUS.OPEN,
        label: "Open",
        hasVisibleNote: false,
        isMuted: true,
        canEdit: true,
        billingHref: "https://prowler.com/pricing",
      },
    };

    const { result } = renderHook(() =>
      useFindingGroupResourceState({
        group,
        filters: {},
        hasHistoricalData: false,
      }),
    );
    const onSetResources = useFindingGroupResourcesMock.mock.calls[0][0]
      .onSetResources as (
      resources: FindingResourceRow[],
      hasMore: boolean,
    ) => void;

    await act(async () => {
      onSetResources([mutedResource], false);
    });

    // When
    await act(async () => {
      await result.current.updateTriageOptimistically(
        {
          findingId: "finding-1",
          findingUid: "finding-uid-1",
          triageId: "triage-1",
          notesCount: 0,
          status: FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
          previousStatus: FINDING_TRIAGE_STATUS.OPEN,
          isMuted: true,
        },
        async () => undefined,
      );
    });

    // Then
    expect(result.current.resources[0]).toEqual(
      expect.objectContaining({
        isMuted: true,
        mutedReason: "Existing mute rule",
      }),
    );
  });
});
