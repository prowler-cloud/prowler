import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoist mocks before imports that chain to next-auth
// ---------------------------------------------------------------------------

const {
  getLatestFindingsByResourceUidMock,
  adaptFindingsByResourceResponseMock,
} = vi.hoisted(() => ({
  getLatestFindingsByResourceUidMock: vi.fn(),
  adaptFindingsByResourceResponseMock: vi.fn(),
}));

vi.mock("@/actions/findings", () => ({
  getLatestFindingsByResourceUid: getLatestFindingsByResourceUidMock,
  adaptFindingsByResourceResponse: adaptFindingsByResourceResponseMock,
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fix 2: AbortController cleanup on unmount
// ---------------------------------------------------------------------------

describe("useResourceDetailDrawer — unmount cleanup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it("should abort the in-flight fetch controller when the hook unmounts", async () => {
    // Given — spy on AbortController.prototype.abort to detect abort calls
    const abortSpy = vi.spyOn(AbortController.prototype, "abort");

    // never-resolving fetch to simulate in-flight request
    getLatestFindingsByResourceUidMock.mockImplementation(
      () => new Promise(() => {}),
    );
    adaptFindingsByResourceResponseMock.mockReturnValue([]);

    const resources = [makeResource()];

    const { result, unmount } = renderHook(() =>
      useResourceDetailDrawer({
        resources,
        checkId: "s3_check",
      }),
    );

    // When — trigger a fetch by opening the drawer
    act(() => {
      result.current.openDrawer(0);
    });

    // Verify a fetch was started
    expect(getLatestFindingsByResourceUidMock).toHaveBeenCalledTimes(1);

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
        checkId: "s3_check",
      }),
    );

    // Then — unmount without any fetch
    unmount();

    // abort should NOT have been called (fetchControllerRef.current is null)
    expect(abortSpy).not.toHaveBeenCalled();
  });
});
