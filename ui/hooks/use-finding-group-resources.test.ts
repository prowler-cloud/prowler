import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useFindingGroupResources } from "./use-finding-group-resources";

type IntersectionCallback = (entries: IntersectionObserverEntry[]) => void;

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

function triggerIntersection() {
  latestObserverCallback?.([
    { isIntersecting: true } as IntersectionObserverEntry,
  ]);
}

const findingGroupActionsMock = vi.hoisted(() => ({
  getLatestFindingGroupResources: vi.fn(),
  getFindingGroupResources: vi.fn(),
  adaptFindingGroupResourcesResponse: vi.fn(),
}));

vi.mock("@/actions/finding-groups", () => findingGroupActionsMock);

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

async function flushAsync() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

describe("useFindingGroupResources", () => {
  beforeEach(() => {
    vi.stubGlobal("IntersectionObserver", MockIntersectionObserver);
    for (const mockFn of Object.values(findingGroupActionsMock)) {
      mockFn.mockReset();
    }
  });

  describe("when mounting", () => {
    it("should fetch page 1 and deliver resources via onSetResources", async () => {
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

      renderHook(() =>
        useFindingGroupResources(
          defaultOptions({ onSetResources, onSetLoading }),
        ),
      );
      await flushAsync();

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
      const apiResponse = makeApiResponse([], { pages: 1 });
      findingGroupActionsMock.getFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        [],
      );

      renderHook(() =>
        useFindingGroupResources(defaultOptions({ hasDateOrScanFilter: true })),
      );
      await flushAsync();

      expect(
        findingGroupActionsMock.getFindingGroupResources,
      ).toHaveBeenCalledTimes(1);
      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).not.toHaveBeenCalled();
    });

    it("should forward the active finding-group filters to the resources endpoint", async () => {
      const apiResponse = makeApiResponse([], { pages: 1 });
      const filters = {
        "filter[status__in]": "PASS",
        "filter[severity__in]": "medium",
        "filter[provider_type__in]": "aws",
      };
      findingGroupActionsMock.getLatestFindingGroupResources.mockResolvedValue(
        apiResponse,
      );
      findingGroupActionsMock.adaptFindingGroupResourcesResponse.mockReturnValue(
        [],
      );

      renderHook(() => useFindingGroupResources(defaultOptions({ filters })));
      await flushAsync();

      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).toHaveBeenCalledWith(
        expect.objectContaining({
          checkId: "check_1",
          page: 1,
          pageSize: 10,
          filters,
        }),
      );
    });
  });

  describe("when all resources fit in one page", () => {
    it("should not fetch page 2 after page 1 completes", async () => {
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

      const { result } = renderHook(() =>
        useFindingGroupResources(defaultOptions()),
      );
      await flushAsync();

      act(() => triggerIntersection());
      await flushAsync();

      expect(
        findingGroupActionsMock.getLatestFindingGroupResources,
      ).toHaveBeenCalledTimes(1);
      expect(result.current.totalCount).toBeNull();
    });
  });
});
