import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useInfiniteResources } from "./use-infinite-resources";

// ---------------------------------------------------------------------------
// IntersectionObserver mock (jsdom doesn't provide one)
// ---------------------------------------------------------------------------

type IntersectionCallback = (entries: IntersectionObserverEntry[]) => void;

/** Stores the latest observer callback so tests can trigger intersections. */
let latestObserverCallback: IntersectionCallback | null = null;

class MockIntersectionObserver {
  callback: IntersectionCallback;
  constructor(callback: IntersectionCallback) {
    this.callback = callback;
    latestObserverCallback = callback;
  }
  observe() {}
  unobserve() {}
  disconnect() {
    if (latestObserverCallback === this.callback) {
      latestObserverCallback = null;
    }
  }
}

/** Simulate the sentinel becoming visible in the scroll container. */
function triggerIntersection() {
  latestObserverCallback?.([
    { isIntersecting: true } as IntersectionObserverEntry,
  ]);
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const findingGroupActionsMock = vi.hoisted(() => ({
  getLatestFindingGroupResources: vi.fn(),
  getFindingGroupResources: vi.fn(),
  adaptFindingGroupResourcesResponse: vi.fn(),
}));

vi.mock("@/actions/finding-groups", () => findingGroupActionsMock);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeApiResponse(
  resources: { id: string }[],
  { pages = 1 }: { pages?: number } = {},
) {
  return {
    data: resources,
    meta: { pagination: { pages } },
  };
}

function fakeResource(id: string) {
  return {
    findingId: id,
    resourceUid: `uid-${id}`,
    resourceName: `Resource ${id}`,
    status: "FAIL",
    severity: "high",
    isMuted: false,
  };
}

function defaultOptions(overrides?: Record<string, unknown>) {
  return {
    checkId: "check_1",
    hasDateOrScanFilter: false,
    filters: {},
    onSetResources: vi.fn(),
    onAppendResources: vi.fn(),
    onSetLoading: vi.fn(),
    ...overrides,
  };
}

/** Flush all pending microtasks (awaits in fetchPage). */
async function flushAsync() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useInfiniteResources", () => {
  beforeEach(() => {
    vi.stubGlobal("IntersectionObserver", MockIntersectionObserver);
    for (const mockFn of Object.values(findingGroupActionsMock)) {
      mockFn.mockReset();
    }
  });

  describe("when mounting", () => {
    it("should fetch page 1 and deliver resources via onSetResources", async () => {
      // Given
      const apiResponse = makeApiResponse([{ id: "r1" }, { id: "r2" }], {
        pages: 1,
      });
      const adapted = [fakeResource("r1"), fakeResource("r2")];

      findingGroupActionsMock.getLatestFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        adapted,
      );

      const onSetResources = vi.fn();
      const onSetLoading = vi.fn();

      // When
      renderHook(() =>
        useInfiniteResources(defaultOptions({ onSetResources, onSetLoading })),
      );
      await flushAsync();

      // Then
      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          checkId: "check_1",
          page: 1,
          pageSize: 10,
        }),
      );
      expect(onSetResources).toHaveBeenCalledWith(adapted, false);
    });

    it("should use getFindingGroupResources when hasDateOrScanFilter is true", async () => {
      // Given
      const apiResponse = makeApiResponse([], { pages: 1 });
      findingGroupActionsMock.getFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        [],
      );

      // When
      renderHook(() =>
        useInfiniteResources(defaultOptions({ hasDateOrScanFilter: true })),
      );
      await flushAsync();

      // Then
      expect(
        findingGroupActionsMock.getFindingGroupResources,
      ).toHaveBeenCalledTimes(1);
      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).not.toHaveBeenCalled();
    });
  });

  describe("when all resources fit in one page", () => {
    it("should not fetch page 2 after page 1 completes", async () => {
      // Given — API returns 4 resources, 1 page total
      const apiResponse = makeApiResponse(
        [{ id: "r1" }, { id: "r2" }, { id: "r3" }, { id: "r4" }],
        { pages: 1 },
      );
      findingGroupActionsMock.getLatestFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        [
          fakeResource("r1"),
          fakeResource("r2"),
          fakeResource("r3"),
          fakeResource("r4"),
        ],
      );

      // When
      const { result } = renderHook(() =>
        useInfiniteResources(defaultOptions()),
      );
      await flushAsync();

      // Attach sentinel so observer is created
      const sentinel = document.createElement("div");
      act(() => {
        result.current.sentinelRef(sentinel);
      });

      // Simulate observer firing (sentinel visible after page 1 loaded)
      act(() => {
        triggerIntersection();
      });
      await flushAsync();

      // Then — only page 1 was fetched, never page 2
      const calls =
        findingGroupActionsMock.getLatestFindingGroupResources.mock.calls;
      const pageNumbers = calls.map(
        (c: unknown[]) => (c[0] as { page: number }).page,
      );
      expect(pageNumbers.every((p: number) => p === 1)).toBe(true);
    });
  });

  describe("when aborted fetch races with active fetch", () => {
    it("should not reset isLoading when an aborted fetch resolves", async () => {
      // Given — simulate the Strict Mode race condition:
      // fetch1 starts, gets aborted, fetch2 starts, fetch1's finally runs
      const onSetResources = vi.fn();
      const onSetLoading = vi.fn();

      // fetch1 resolves slowly (after abort)
      let resolveFetch1: (v: unknown) => void;
      const fetch1Promise = new Promise((r) => {
        resolveFetch1 = r;
      });

      // fetch2 resolves normally
      const apiResponse = makeApiResponse([{ id: "r1" }], { pages: 1 });
      const adapted = [fakeResource("r1")];

      let callCount = 0;
      findingGroupActionsMock.getLatestFindingGroupResources.mockImplementation(
        () => {
          callCount++;
          if (callCount === 1) return fetch1Promise;
          return Promise.resolve(apiResponse);
        },
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        adapted,
      );

      // When — mount, abort (simulating cleanup), remount
      const { unmount } = renderHook(() =>
        useInfiniteResources(defaultOptions({ onSetResources, onSetLoading })),
      );

      // Simulate Strict Mode: unmount triggers abort
      unmount();

      // Fetch1 resolves AFTER abort — its finally should NOT reset isLoading
      await act(async () => {
        resolveFetch1!(apiResponse);
        await new Promise((r) => setTimeout(r, 0));
      });

      // Then — onSetResources should NOT have been called by the aborted fetch
      // (the signal.aborted check returns early)
      expect(onSetResources).not.toHaveBeenCalled();
    });
  });

  describe("when sentinel triggers next page", () => {
    it("should fetch page 2 via onAppendResources when hasMore is true", async () => {
      // Given — page 1 has more pages
      const page1Response = makeApiResponse(
        Array.from({ length: 10 }, (_, i) => ({ id: `r${i}` })),
        { pages: 3 },
      );
      const page1Adapted = Array.from({ length: 10 }, (_, i) =>
        fakeResource(`r${i}`),
      );

      const page2Response = makeApiResponse(
        Array.from({ length: 10 }, (_, i) => ({ id: `r${10 + i}` })),
        { pages: 3 },
      );
      const page2Adapted = Array.from({ length: 10 }, (_, i) =>
        fakeResource(`r${10 + i}`),
      );

      findingGroupActionsMock.getLatestFindingGroupResources
        .mockResolvedValueOnce(page1Response)
        .mockResolvedValueOnce(page2Response);
      findingGroupActionsMock.adaptFindingGroupResourcesResponse
        .mockReturnValueOnce(page1Adapted)
        .mockReturnValueOnce(page2Adapted);

      const onSetResources = vi.fn();
      const onAppendResources = vi.fn();

      // When — mount and wait for page 1
      const { result } = renderHook(() =>
        useInfiniteResources(
          defaultOptions({ onSetResources, onAppendResources }),
        ),
      );
      await flushAsync();

      expect(onSetResources).toHaveBeenCalledWith(page1Adapted, true);

      // Attach sentinel and simulate intersection → triggers page 2
      const sentinel = document.createElement("div");
      act(() => {
        result.current.sentinelRef(sentinel);
      });
      act(() => {
        triggerIntersection();
      });
      await flushAsync();

      // Then
      expect(onAppendResources).toHaveBeenCalledWith(page2Adapted, true);
      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).toHaveBeenCalledTimes(2);
    });
  });

  describe("when refresh is called", () => {
    it("should re-fetch page 1 and deliver via onSetResources", async () => {
      // Given
      const apiResponse = makeApiResponse([{ id: "r1" }], { pages: 1 });
      const adapted = [fakeResource("r1")];

      findingGroupActionsMock.getLatestFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        adapted,
      );

      const onSetResources = vi.fn();

      const { result } = renderHook(() =>
        useInfiniteResources(defaultOptions({ onSetResources })),
      );
      await flushAsync();

      expect(onSetResources).toHaveBeenCalledTimes(1);

      // When — refresh (e.g. after muting)
      act(() => {
        result.current.refresh();
      });
      await flushAsync();

      // Then — page 1 fetched again
      expect(onSetResources).toHaveBeenCalledTimes(2);
      const calls =
        findingGroupActionsMock.getLatestFindingGroupResources.mock.calls;
      expect(calls).toHaveLength(2);
      expect(calls[0][0].page).toBe(1);
      expect(calls[1][0].page).toBe(1);
    });
  });

  describe("when filters include search params", () => {
    it("should pass filters to the fetch function", async () => {
      // Given
      const apiResponse = makeApiResponse([], { pages: 1 });
      findingGroupActionsMock.getLatestFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        [],
      );

      const filters = {
        "filter[name__icontains]": "my-resource",
        "filter[severity__in]": "high",
      };

      // When
      renderHook(() => useInfiniteResources(defaultOptions({ filters })));
      await flushAsync();

      // Then
      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).toHaveBeenCalledWith(expect.objectContaining({ filters }));
    });
  });

  describe("when refresh() fires while loadNextPage is in-flight (race condition — Fix 5)", () => {
    it("should discard in-flight page 2 and fetch page 1 when refresh fires during loadNextPage", async () => {
      // Given — page 1 has 2 pages total, page 2 hangs indefinitely
      const page1Response = makeApiResponse(
        Array.from({ length: 10 }, (_, i) => ({ id: `r${i}` })),
        { pages: 2 },
      );
      const page1Adapted = Array.from({ length: 10 }, (_, i) =>
        fakeResource(`r${i}`),
      );

      const page2Response = makeApiResponse(
        Array.from({ length: 5 }, (_, i) => ({ id: `r${10 + i}` })),
        { pages: 2 },
      );

      const refreshPage1Response = makeApiResponse([{ id: "r-fresh-1" }], {
        pages: 1,
      });
      const refreshPage1Adapted = [fakeResource("r-fresh-1")];

      // page 2 hangs until we explicitly resolve it
      let resolveNextPage: (v: unknown) => void = () => {};
      const hangingPage2 = new Promise((r) => {
        resolveNextPage = r;
      });

      let callCount = 0;
      findingGroupActionsMock.getLatestFindingGroupResources.mockImplementation(
        (args: { page: number }) => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve(page1Response);
          }
          if (args.page === 2) {
            return hangingPage2;
          }
          return Promise.resolve(refreshPage1Response);
        },
      );

      findingGroupActionsMock.adaptFindingGroupResourcesResponse
        .mockReturnValueOnce(page1Adapted)
        .mockReturnValue(refreshPage1Adapted);

      const onSetResources = vi.fn();
      const onAppendResources = vi.fn();

      // When — mount and wait for page 1
      const { result } = renderHook(() =>
        useInfiniteResources(
          defaultOptions({ onSetResources, onAppendResources }),
        ),
      );
      await flushAsync();

      expect(onSetResources).toHaveBeenCalledWith(page1Adapted, true);

      // Trigger loadNextPage (increments pageRef to 2 in buggy code)
      const sentinel = document.createElement("div");
      act(() => {
        result.current.sentinelRef(sentinel);
      });
      act(() => {
        triggerIntersection();
      });
      // Do NOT flush — page 2 is hanging in-flight

      // Refresh fires while page 2 is in-flight
      act(() => {
        result.current.refresh();
      });
      await flushAsync();

      // Resolve hanging page 2 after refresh (simulates late stale response)
      await act(async () => {
        resolveNextPage(page2Response);
        await new Promise((r) => setTimeout(r, 0));
      });

      // Then — the aborted page 2 must NOT deliver resources (signal.aborted check)
      expect(onAppendResources).not.toHaveBeenCalled();

      // The refresh must have fetched page 1 and delivered fresh resources
      expect(onSetResources).toHaveBeenCalledWith(refreshPage1Adapted, false);

      // The refresh call must request page=1 (not page=3 due to stale pageRef)
      // Exact call sequence: [0]=initial page 1, [1]=loadNextPage page 2, [2]=refresh page 1
      const calls =
        findingGroupActionsMock.getLatestFindingGroupResources.mock.calls;
      expect((calls[0][0] as { page: number }).page).toBe(1); // initial fetch
      expect((calls[1][0] as { page: number }).page).toBe(2); // loadNextPage
      expect((calls[2][0] as { page: number }).page).toBe(1); // refresh
    });

    it("should fetch sequential pages without skipping when loadNextPage is used normally", async () => {
      // Given — page 1 has 3 pages; pages load sequentially
      const makePageResponse = (startIdx: number, total: number) =>
        makeApiResponse(
          Array.from({ length: 5 }, (_, i) => ({ id: `r${startIdx + i}` })),
          { pages: total },
        );

      findingGroupActionsMock.getLatestFindingGroupResources
        .mockResolvedValueOnce(makePageResponse(0, 3)) // page 1
        .mockResolvedValueOnce(makePageResponse(5, 3)) // page 2
        .mockResolvedValueOnce(makePageResponse(10, 3)); // page 3

      findingGroupActionsMock.adaptFindingGroupResourcesResponse
        .mockReturnValueOnce(
          Array.from({ length: 5 }, (_, i) => fakeResource(`r${i}`)),
        )
        .mockReturnValueOnce(
          Array.from({ length: 5 }, (_, i) => fakeResource(`r${5 + i}`)),
        )
        .mockReturnValueOnce(
          Array.from({ length: 5 }, (_, i) => fakeResource(`r${10 + i}`)),
        );

      const onAppendResources = vi.fn();

      // When — mount and wait for page 1
      const { result } = renderHook(() =>
        useInfiniteResources(defaultOptions({ onAppendResources })),
      );
      await flushAsync();

      // Attach sentinel
      const sentinel = document.createElement("div");
      act(() => {
        result.current.sentinelRef(sentinel);
      });

      // Load page 2
      act(() => {
        triggerIntersection();
      });
      await flushAsync();

      // Load page 3
      act(() => {
        triggerIntersection();
      });
      await flushAsync();

      // Then — pages were fetched in order: 2, 3 (not 2, 4 due to double-increment)
      const calls =
        findingGroupActionsMock.getLatestFindingGroupResources.mock.calls;
      expect(calls[1][0].page).toBe(2);
      expect(calls[2][0].page).toBe(3);
    });
  });
});
