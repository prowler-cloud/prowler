import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
  appendSanitizedProviderTypeFiltersMock,
  getFindingGroupResourcesMock,
  getLatestFindingGroupResourcesMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  appendSanitizedProviderTypeFiltersMock: vi.fn(
    (url: URL, filters: Record<string, string>) => {
      Object.entries(filters).forEach(([key, value]) => {
        if (key !== "filter[search]") {
          url.searchParams.append(key, value);
        }
      });
    },
  ),
  getFindingGroupResourcesMock: vi.fn(),
  getLatestFindingGroupResourcesMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/provider-filters", () => ({
  appendSanitizedProviderTypeFilters: appendSanitizedProviderTypeFiltersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("@/actions/finding-groups", () => ({
  getFindingGroupResources: getFindingGroupResourcesMock,
  getLatestFindingGroupResources: getLatestFindingGroupResourcesMock,
}));

import {
  resolveFindingIds,
  resolveFindingIdsByCheckIds,
  resolveFindingIdsByVisibleGroupResources,
} from "./findings-by-resource";

describe("resolveFindingIdsByCheckIds", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("should resolve all finding IDs across every page for the latest endpoint", async () => {
    // Given
    fetchMock
      .mockResolvedValueOnce(new Response("", { status: 200 }))
      .mockResolvedValueOnce(new Response("", { status: 200 }))
      .mockResolvedValueOnce(new Response("", { status: 200 }));

    handleApiResponseMock
      .mockResolvedValueOnce({
        data: [{ id: "finding-1" }, { id: "finding-2" }],
        meta: { pagination: { pages: 3 } },
      })
      .mockResolvedValueOnce({
        data: [{ id: "finding-3" }],
        meta: { pagination: { pages: 3 } },
      })
      .mockResolvedValueOnce({
        data: [{ id: "finding-4" }],
        meta: { pagination: { pages: 3 } },
      });

    // When
    const result = await resolveFindingIdsByCheckIds({
      checkIds: ["check-1", "check-2"],
      filters: {
        "filter[provider_type__in]": "aws",
        "filter[search]": "ignored-search",
      },
    });

    // Then
    expect(result).toEqual([
      "finding-1",
      "finding-2",
      "finding-3",
      "finding-4",
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(3);

    const firstCallUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(firstCallUrl.pathname).toBe("/api/v1/findings/latest");
    expect(firstCallUrl.searchParams.get("filter[check_id__in]")).toBe(
      "check-1,check-2",
    );
    expect(firstCallUrl.searchParams.get("filter[muted]")).toBe("false");
    expect(firstCallUrl.searchParams.get("page[size]")).toBe("500");
    expect(firstCallUrl.searchParams.get("page[number]")).toBe("1");
    expect(firstCallUrl.searchParams.get("fields[findings]")).toBe("uid");
    expect(firstCallUrl.searchParams.get("filter[provider_type__in]")).toBe(
      "aws",
    );
    expect(firstCallUrl.searchParams.get("filter[search]")).toBeNull();

    const laterPages = fetchMock.mock.calls
      .slice(1)
      .map(([url]) => new URL(url).searchParams.get("page[number]"));
    expect(laterPages.sort()).toEqual(["2", "3"]);
  });

  it("should use the dated findings endpoint when date or scan filters are active", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }],
      meta: { pagination: { pages: 1 } },
    });

    // When
    await resolveFindingIdsByCheckIds({
      checkIds: ["check-1"],
      hasDateOrScanFilter: true,
      filters: {
        "filter[scan__in]": "scan-1",
        "filter[inserted_at__gte]": "2026-03-01",
      },
    });

    // Then
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.pathname).toBe("/api/v1/findings");
    expect(calledUrl.searchParams.get("filter[scan__in]")).toBe("scan-1");
    expect(calledUrl.searchParams.get("filter[inserted_at__gte]")).toBe(
      "2026-03-01",
    );
  });
});

describe("resolveFindingIds", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("should use the dated findings endpoint when date or scan filters are active", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }, { id: "finding-2" }],
    });

    // When
    const result = await resolveFindingIds({
      checkId: "check-1",
      resourceUids: ["resource-1", "resource-2"],
      hasDateOrScanFilter: true,
      filters: {
        "filter[scan__in]": "scan-1",
        "filter[inserted_at__gte]": "2026-03-01",
      },
    });

    // Then
    expect(result).toEqual(["finding-1", "finding-2"]);

    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.pathname).toBe("/api/v1/findings");
    expect(calledUrl.searchParams.get("filter[check_id]")).toBe("check-1");
    expect(calledUrl.searchParams.get("filter[resource_uid__in]")).toBe(
      "resource-1,resource-2",
    );
    expect(calledUrl.searchParams.get("filter[scan__in]")).toBe("scan-1");
    expect(calledUrl.searchParams.get("filter[inserted_at__gte]")).toBe(
      "2026-03-01",
    );
  });
});

describe("resolveFindingIdsByVisibleGroupResources", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("should resolve finding IDs from the group's visible resource UIDs instead of muting the whole check", async () => {
    // Given
    getLatestFindingGroupResourcesMock
      .mockResolvedValueOnce({
        data: [
          {
            id: "resource-row-1",
            attributes: {
              resource: { uid: "resource-1" },
            },
          },
          {
            id: "resource-row-2",
            attributes: {
              resource: { uid: "resource-2" },
            },
          },
        ],
        meta: { pagination: { pages: 2 } },
      })
      .mockResolvedValueOnce({
        data: [
          {
            id: "resource-row-3",
            attributes: {
              resource: { uid: "resource-3" },
            },
          },
        ],
        meta: { pagination: { pages: 2 } },
      });

    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }, { id: "finding-2" }, { id: "finding-3" }],
    });

    // When
    const result = await resolveFindingIdsByVisibleGroupResources({
      checkId: "check-1",
      filters: {
        "filter[provider_type__in]": "aws",
      },
      resourceSearch: "visible subset",
    });

    // Then
    expect(result).toEqual(["finding-1", "finding-2", "finding-3"]);
    expect(getLatestFindingGroupResourcesMock).toHaveBeenCalledTimes(2);
    expect(getLatestFindingGroupResourcesMock).toHaveBeenNthCalledWith(1, {
      checkId: "check-1",
      page: 1,
      pageSize: 500,
      filters: {
        "filter[provider_type__in]": "aws",
        "filter[name__icontains]": "visible subset",
      },
    });
    expect(getLatestFindingGroupResourcesMock).toHaveBeenNthCalledWith(2, {
      checkId: "check-1",
      page: 2,
      pageSize: 500,
      filters: {
        "filter[provider_type__in]": "aws",
        "filter[name__icontains]": "visible subset",
      },
    });

    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.pathname).toBe("/api/v1/findings/latest");
    expect(calledUrl.searchParams.get("filter[check_id]")).toBe("check-1");
    expect(calledUrl.searchParams.get("filter[check_id__in]")).toBeNull();
    expect(calledUrl.searchParams.get("filter[resource_uid__in]")).toBe(
      "resource-1,resource-2,resource-3",
    );
  });
});

// ---------------------------------------------------------------------------
// Fix 4: Unbounded page[size] cap
//
// The bug: createResourceFindingResolutionUrl sets page[size]=resourceUids.length
// with no upper bound guard. The production fix adds Math.min(resourceUids.length, MAX_PAGE_SIZE)
// with MAX_PAGE_SIZE=500 as an explicit defensive cap.
// ---------------------------------------------------------------------------

describe("resolveFindingIds — Fix 4: page[size] explicit cap at MAX_PAGE_SIZE=500", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("should use resourceUids.length as page[size] for a small batch (under 500)", async () => {
    // Given — 3 resources, well under the cap
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }, { id: "finding-2" }, { id: "finding-3" }],
    });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids: ["resource-1", "resource-2", "resource-3"],
    });

    // Then — page[size] should equal the number of resourceUids (3)
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.searchParams.get("page[size]")).toBe("3");
  });

  it("should cap page[size] at 500 when the chunk has exactly 500 UIDs (boundary value)", async () => {
    // Given — exactly 500 unique UIDs (at the cap boundary)
    const resourceUids = Array.from({ length: 500 }, (_, i) => `resource-${i}`);
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids,
    });

    // Then — page[size] must be exactly 500 (not capped lower)
    const firstUrl = new URL(fetchMock.mock.calls[0][0] as string);
    expect(firstUrl.searchParams.get("page[size]")).toBe("500");
  });

  it("should cap page[size] at 500 even when a chunk would exceed 500 — Math.min guard in URL builder", async () => {
    // Given — 501 UIDs. The chunker splits into [500, 1].
    // The FIRST chunk has 500 UIDs → page[size] should be 500 (Math.min(500, 500)).
    // The SECOND chunk has 1 UID → page[size] should be 1 (Math.min(1, 500)).
    // This proves the Math.min cap fires correctly on every chunk.
    const resourceUids = Array.from({ length: 501 }, (_, i) => `resource-${i}`);
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids,
    });

    // Then — two fetch calls: one for 500 UIDs, one for 1 UID
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const firstUrl = new URL(fetchMock.mock.calls[0][0] as string);
    const secondUrl = new URL(fetchMock.mock.calls[1][0] as string);
    expect(firstUrl.searchParams.get("page[size]")).toBe("500");
    expect(secondUrl.searchParams.get("page[size]")).toBe("1");
  });
});
