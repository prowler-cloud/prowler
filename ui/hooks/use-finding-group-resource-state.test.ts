import { renderHook } from "@testing-library/react";
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

import { type FindingGroupRow, FINDINGS_ROW_TYPE } from "@/types";

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
});
