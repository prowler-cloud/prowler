import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks before imports that chain to next-auth
// ---------------------------------------------------------------------------

const {
  getFindingByIdMock,
  getLatestFindingsByResourceUidMock,
  adaptFindingsByResourceResponseMock,
} = vi.hoisted(() => ({
  getFindingByIdMock: vi.fn(),
  getLatestFindingsByResourceUidMock: vi.fn(),
  adaptFindingsByResourceResponseMock: vi.fn(),
}));

vi.mock("@/actions/findings", () => ({
  getFindingById: getFindingByIdMock,
  getLatestFindingsByResourceUid: getLatestFindingsByResourceUidMock,
  adaptFindingsByResourceResponse: adaptFindingsByResourceResponseMock,
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import type { ResourceDrawerFinding } from "@/actions/findings";
import type { FindingResourceRow } from "@/types";

import { useResourceDetailDrawer } from "./use-resource-detail-drawer";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeResource(
  overrides?: Partial<FindingResourceRow>,
): FindingResourceRow {
  return {
    id: "row-1",
    rowType: "resource" as const,
    findingId: "finding-1",
    checkId: "s3_check",
    providerType: "aws",
    providerAlias: "prod",
    providerUid: "123",
    resourceName: "my-bucket",
    resourceGroup: "default",
    resourceUid: "arn:aws:s3:::my-bucket",
    service: "s3",
    region: "us-east-1",
    severity: "critical",
    status: "FAIL",
    isMuted: false,
    mutedReason: undefined,
    firstSeenAt: null,
    lastSeenAt: null,
    ...overrides,
  } as FindingResourceRow;
}

function makeDrawerFinding(
  overrides?: Partial<ResourceDrawerFinding>,
): ResourceDrawerFinding {
  return {
    id: "finding-1",
    uid: "uid-1",
    checkId: "s3_check",
    checkTitle: "S3 Check",
    status: "FAIL",
    severity: "high",
    delta: null,
    isMuted: false,
    mutedReason: null,
    firstSeenAt: null,
    updatedAt: null,
    resourceId: "resource-1",
    resourceUid: "arn:aws:s3:::my-bucket",
    resourceName: "my-bucket",
    resourceService: "s3",
    resourceRegion: "us-east-1",
    resourceType: "bucket",
    resourceGroup: "default",
    providerType: "aws",
    providerAlias: "prod",
    providerUid: "123",
    risk: "high",
    description: "desc",
    statusExtended: "status",
    complianceFrameworks: [],
    categories: [],
    remediation: {
      recommendation: { text: "", url: "" },
      code: { cli: "", other: "", nativeiac: "", terraform: "" },
    },
    additionalUrls: [],
    scan: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fix 2: AbortController cleanup on unmount
// ---------------------------------------------------------------------------

describe("useResourceDetailDrawer — unmount cleanup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    getLatestFindingsByResourceUidMock.mockResolvedValue({ data: [] });
  });

  it("should abort the in-flight fetch controller when the hook unmounts", async () => {
    // Given — spy on AbortController.prototype.abort to detect abort calls
    const abortSpy = vi.spyOn(AbortController.prototype, "abort");

    // never-resolving fetch to simulate in-flight request
    getFindingByIdMock.mockImplementation(() => new Promise(() => {}));
    adaptFindingsByResourceResponseMock.mockReturnValue([]);

    const resources = [makeResource()];

    const { result, unmount } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    // When — trigger a fetch by opening the drawer
    act(() => {
      result.current.openDrawer(0);
    });

    // Verify a fetch was started
    expect(getFindingByIdMock).toHaveBeenCalledTimes(1);

    // Reset spy count to detect only the unmount abort
    abortSpy.mockClear();

    // Then — unmount while fetch is in flight
    unmount();

    // The abort should have been called on unmount
    expect(abortSpy).toHaveBeenCalledTimes(1);
  });

  it("should not abort when no fetch has been started yet", () => {
    // Given — spy on abort
    const abortSpy = vi.spyOn(AbortController.prototype, "abort");

    const resources = [makeResource()];

    // When — render without opening drawer (no fetch started)
    const { unmount } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    // Then — unmount without any fetch
    unmount();

    // abort should NOT have been called (fetchControllerRef.current is null)
    expect(abortSpy).not.toHaveBeenCalled();
  });
});

describe("useResourceDetailDrawer — other findings filtering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLatestFindingsByResourceUidMock.mockResolvedValue({ data: [] });
  });

  it("should load other findings from the current resource uid and exclude the current finding", async () => {
    const resources = [makeResource()];

    // Given
    getFindingByIdMock.mockResolvedValue({ data: ["detail"] });
    getLatestFindingsByResourceUidMock.mockResolvedValue({
      data: ["resource"],
    });
    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => {
        if (response.data[0] === "detail") {
          return [
            makeDrawerFinding({
              id: "finding-1",
              checkId: "s3_check",
              checkTitle: "Current",
              status: "MANUAL",
              severity: "informational",
            }),
          ];
        }

        return [
          makeDrawerFinding({
            id: "finding-3",
            checkTitle: "First other finding",
            status: "FAIL",
            severity: "high",
          }),
          makeDrawerFinding({
            id: "finding-1",
            checkTitle: "Current finding duplicate from resource fetch",
            status: "FAIL",
            severity: "critical",
          }),
          makeDrawerFinding({
            id: "finding-4",
            checkTitle: "Manual finding should be filtered out",
            status: "MANUAL",
            severity: "low",
          }),
          makeDrawerFinding({
            id: "finding-5",
            checkTitle: "Second other finding",
            status: "FAIL",
            severity: "medium",
          }),
        ];
      },
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    // Then
    expect(getFindingByIdMock).toHaveBeenCalledWith(
      "finding-1",
      "resources,scan.provider",
      { source: "resource-detail-drawer" },
    );
    expect(getLatestFindingsByResourceUidMock).toHaveBeenCalledWith({
      resourceUid: "arn:aws:s3:::my-bucket",
      pageSize: 50,
      includeMuted: false,
    });
    expect(result.current.currentFinding?.id).toBe("finding-1");
    expect(result.current.otherFindings.map((finding) => finding.id)).toEqual([
      "finding-3",
      "finding-5",
    ]);
  });

  it("should skip loading other findings for synthetic IaC resources and keep the current detail on findingId", async () => {
    const resources = [
      makeResource({
        findingId: "synthetic-finding",
        resourceUid: "synthetic://iac-resource",
      }),
    ];

    // Given
    getFindingByIdMock.mockResolvedValue({ data: ["detail"] });
    adaptFindingsByResourceResponseMock.mockReturnValue([
      makeDrawerFinding({
        id: "synthetic-finding",
        checkId: "s3_check",
        status: "MANUAL",
        severity: "informational",
      }),
    ]);

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
        canLoadOtherFindings: false,
      }),
    );

    await act(async () => {
      // When
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    // Then
    expect(getFindingByIdMock).toHaveBeenCalledWith(
      "synthetic-finding",
      "resources,scan.provider",
      { source: "resource-detail-drawer" },
    );
    expect(getLatestFindingsByResourceUidMock).not.toHaveBeenCalled();
    expect(result.current.currentFinding?.id).toBe("synthetic-finding");
    expect(result.current.otherFindings).toEqual([]);
  });

  it("should request muted findings only when explicitly enabled", async () => {
    const resources = [makeResource()];

    getLatestFindingsByResourceUidMock.mockResolvedValue({ data: [] });
    adaptFindingsByResourceResponseMock.mockReturnValue([makeDrawerFinding()]);

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
        includeMutedInOtherFindings: true,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    expect(getLatestFindingsByResourceUidMock).toHaveBeenCalledWith({
      resourceUid: "arn:aws:s3:::my-bucket",
      pageSize: 50,
      includeMuted: true,
    });
  });

  it("should keep isNavigating true for a cached resource long enough to render skeletons", async () => {
    vi.useFakeTimers();

    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        resourceUid: "arn:aws:s3:::first-bucket",
        resourceName: "first-bucket",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        resourceUid: "arn:aws:s3:::second-bucket",
        resourceName: "second-bucket",
      }),
    ];

    getFindingByIdMock.mockImplementation(async (findingId: string) => ({
      data: [findingId],
    }));
    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => [
        makeDrawerFinding({
          id: response.data[0],
          resourceUid:
            response.data[0] === "finding-1"
              ? "arn:aws:s3:::first-bucket"
              : "arn:aws:s3:::second-bucket",
          resourceName:
            response.data[0] === "finding-1" ? "first-bucket" : "second-bucket",
        }),
      ],
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    await act(async () => {
      result.current.navigateNext();
      await Promise.resolve();
    });

    expect(result.current.currentIndex).toBe(1);
    expect(result.current.currentFinding?.id).toBe("finding-2");

    act(() => {
      result.current.navigatePrev();
    });

    expect(result.current.currentIndex).toBe(0);
    expect(result.current.isNavigating).toBe(true);

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      vi.runAllTimers();
      await Promise.resolve();
    });

    expect(result.current.isNavigating).toBe(false);
    expect(result.current.currentFinding?.id).toBe("finding-1");

    vi.useRealTimers();
  });

  it("should keep isNavigating true for a fast uncached navigation long enough to avoid flicker", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-04-08T15:00:00.000Z"));

    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        resourceUid: "arn:aws:s3:::first-bucket",
        resourceName: "first-bucket",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        resourceUid: "arn:aws:s3:::second-bucket",
        resourceName: "second-bucket",
      }),
    ];

    getFindingByIdMock.mockImplementation(async (findingId: string) => ({
      data: [findingId],
    }));
    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => [
        makeDrawerFinding({
          id: response.data[0],
          resourceUid:
            response.data[0] === "finding-1"
              ? "arn:aws:s3:::first-bucket"
              : "arn:aws:s3:::second-bucket",
          resourceName:
            response.data[0] === "finding-1" ? "first-bucket" : "second-bucket",
        }),
      ],
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    act(() => {
      result.current.navigateNext();
    });

    expect(result.current.currentIndex).toBe(1);
    expect(result.current.isNavigating).toBe(true);

    await act(async () => {
      await Promise.resolve();
    });

    expect(result.current.currentFinding?.id).toBe("finding-2");
    expect(result.current.isNavigating).toBe(true);

    await act(async () => {
      vi.advanceTimersByTime(119);
      await Promise.resolve();
    });

    expect(result.current.isNavigating).toBe(true);

    await act(async () => {
      vi.advanceTimersByTime(1);
      await Promise.resolve();
    });

    await act(async () => {
      vi.runOnlyPendingTimers();
      await Promise.resolve();
    });

    expect(result.current.isNavigating).toBe(false);

    vi.useRealTimers();
  });

  it("should update checkMeta when navigating to a resource with a different check", async () => {
    // Given
    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        checkId: "s3_check",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        checkId: "ec2_check",
        resourceUid: "arn:aws:ec2:::instance/i-123",
        resourceName: "instance-1",
        service: "ec2",
      }),
    ];

    getFindingByIdMock.mockImplementation(async (findingId: string) => ({
      data: [findingId],
    }));
    getLatestFindingsByResourceUidMock.mockResolvedValue({ data: [] });
    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => [
        response.data[0] === "finding-1"
          ? makeDrawerFinding({
              id: "finding-1",
              checkId: "s3_check",
              checkTitle: "S3 Check",
              description: "s3 description",
            })
          : makeDrawerFinding({
              id: "finding-2",
              checkId: "ec2_check",
              checkTitle: "EC2 Check",
              description: "ec2 description",
            }),
      ],
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    // When
    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    expect(result.current.checkMeta?.checkTitle).toBe("S3 Check");

    await act(async () => {
      result.current.navigateNext();
      await Promise.resolve();
    });

    // Then
    expect(result.current.checkMeta?.checkTitle).toBe("EC2 Check");
    expect(result.current.checkMeta?.description).toBe("ec2 description");
  });

  it("should keep the previous check metadata cached while reopening until the new finding arrives", async () => {
    // Given
    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        checkId: "s3_check",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        checkId: "ec2_check",
        resourceUid: "arn:aws:ec2:::instance/i-123",
        resourceName: "instance-1",
        service: "ec2",
      }),
    ];

    let resolveSecondFinding: ((value: { data: string[] }) => void) | null =
      null;

    getFindingByIdMock.mockImplementation((findingId: string) => {
      if (findingId === "finding-2") {
        return new Promise((resolve) => {
          resolveSecondFinding = resolve;
        });
      }

      return Promise.resolve({ data: [findingId] });
    });
    getLatestFindingsByResourceUidMock.mockResolvedValue({ data: [] });
    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => [
        response.data[0] === "finding-1"
          ? makeDrawerFinding({
              id: "finding-1",
              checkId: "s3_check",
              checkTitle: "S3 Check",
              description: "s3 description",
            })
          : makeDrawerFinding({
              id: "finding-2",
              checkId: "ec2_check",
              checkTitle: "EC2 Check",
              description: "ec2 description",
            }),
      ],
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    expect(result.current.checkMeta?.checkTitle).toBe("S3 Check");

    // When
    act(() => {
      result.current.closeDrawer();
      result.current.openDrawer(1);
    });

    // Then
    expect(result.current.isOpen).toBe(true);
    expect(result.current.currentIndex).toBe(1);
    expect(result.current.currentFinding).toBeNull();
    expect(result.current.checkMeta?.checkTitle).toBe("S3 Check");

    await act(async () => {
      resolveSecondFinding?.({ data: ["finding-2"] });
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.checkMeta?.checkTitle).toBe("EC2 Check");
    expect(result.current.checkMeta?.description).toBe("ec2 description");
  });

  it("should clear the previous resource findings when navigation to the next resource fails", async () => {
    // Given
    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        resourceUid: "arn:aws:s3:::first-bucket",
        resourceName: "first-bucket",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        resourceUid: "arn:aws:s3:::second-bucket",
        resourceName: "second-bucket",
      }),
    ];

    getFindingByIdMock.mockImplementation(async (findingId: string) => {
      if (findingId === "finding-2") {
        throw new Error("Fetch failed");
      }

      return { data: [findingId] };
    });

    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => [
        makeDrawerFinding({
          id: response.data[0],
          resourceUid:
            response.data[0] === "finding-1"
              ? "arn:aws:s3:::first-bucket"
              : "arn:aws:s3:::second-bucket",
          resourceName:
            response.data[0] === "finding-1" ? "first-bucket" : "second-bucket",
        }),
      ],
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    expect(result.current.currentFinding?.resourceUid).toBe(
      "arn:aws:s3:::first-bucket",
    );
    expect(result.current.checkMeta?.checkTitle).toBe("S3 Check");

    // When
    await act(async () => {
      result.current.navigateNext();
      await Promise.resolve();
    });

    // Then
    expect(result.current.currentIndex).toBe(1);
    expect(result.current.currentFinding).toBeNull();
    expect(result.current.otherFindings).toEqual([]);
    expect(result.current.checkMeta).toBeNull();
  });

  it("should clear other findings immediately while the next resource is loading", async () => {
    // Given
    const resources = [
      makeResource({
        id: "row-1",
        findingId: "finding-1",
        resourceUid: "arn:aws:s3:::first-bucket",
        resourceName: "first-bucket",
      }),
      makeResource({
        id: "row-2",
        findingId: "finding-2",
        resourceUid: "arn:aws:s3:::second-bucket",
        resourceName: "second-bucket",
      }),
    ];

    let resolveSecondFinding: ((value: { data: string[] }) => void) | null =
      null;
    let resolveSecondResource: ((value: { data: string[] }) => void) | null =
      null;

    getFindingByIdMock.mockImplementation((findingId: string) => {
      if (findingId === "finding-2") {
        return new Promise((resolve) => {
          resolveSecondFinding = resolve;
        });
      }

      return Promise.resolve({ data: [findingId] });
    });

    getLatestFindingsByResourceUidMock.mockImplementation(
      ({ resourceUid }: { resourceUid: string }) => {
        if (resourceUid === "arn:aws:s3:::second-bucket") {
          return new Promise((resolve) => {
            resolveSecondResource = resolve;
          });
        }

        return Promise.resolve({ data: ["resource-1"] });
      },
    );

    adaptFindingsByResourceResponseMock.mockImplementation(
      (response: { data: string[] }) => {
        if (response.data[0] === "finding-1") {
          return [makeDrawerFinding({ id: "finding-1" })];
        }

        if (response.data[0] === "finding-2") {
          return [
            makeDrawerFinding({
              id: "finding-2",
              resourceUid: "arn:aws:s3:::second-bucket",
              resourceName: "second-bucket",
            }),
          ];
        }

        if (response.data[0] === "resource-1") {
          return [
            makeDrawerFinding({
              id: "finding-3",
              checkTitle: "First bucket other finding",
              resourceUid: "arn:aws:s3:::first-bucket",
            }),
          ];
        }

        return [
          makeDrawerFinding({
            id: "finding-4",
            checkTitle: "Second bucket other finding",
            resourceUid: "arn:aws:s3:::second-bucket",
          }),
        ];
      },
    );

    const { result } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
      }),
    );

    await act(async () => {
      result.current.openDrawer(0);
      await Promise.resolve();
    });

    expect(result.current.otherFindings.map((finding) => finding.id)).toEqual([
      "finding-3",
    ]);

    // When
    act(() => {
      result.current.navigateNext();
    });

    // Then
    expect(result.current.currentIndex).toBe(1);
    expect(result.current.currentFinding).toBeNull();
    expect(result.current.otherFindings).toEqual([]);

    await act(async () => {
      resolveSecondFinding?.({ data: ["finding-2"] });
      resolveSecondResource?.({ data: ["resource-2"] });
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(result.current.otherFindings.map((finding) => finding.id)).toEqual([
      "finding-4",
    ]);
  });
});
