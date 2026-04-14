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

describe("resolveFindingIdsByVisibleGroupResources", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("extracts finding_id directly from group resources without a second resolution round-trip", async () => {
    // Given — the group resources endpoint returns finding_id in each resource
    getLatestFindingGroupResourcesMock
      .mockResolvedValueOnce({
        data: [
          {
            id: "resource-row-1",
            attributes: { finding_id: "finding-1" },
          },
          {
            id: "resource-row-2",
            attributes: { finding_id: "finding-2" },
          },
        ],
        meta: { pagination: { pages: 2 } },
      })
      .mockResolvedValueOnce({
        data: [
          {
            id: "resource-row-3",
            attributes: { finding_id: "finding-3" },
          },
        ],
        meta: { pagination: { pages: 2 } },
      });

    // When
    const result = await resolveFindingIdsByVisibleGroupResources({
      checkId: "check-1",
      filters: {
        "filter[provider_type__in]": "aws",
      },
      resourceSearch: "visible subset",
    });

    // Then — finding IDs come directly from the group resources response
    expect(result).toEqual(["finding-1", "finding-2", "finding-3"]);

    // No second round-trip to /findings/latest
    expect(fetchMock).not.toHaveBeenCalled();

    // Group resources endpoint was paginated with correct filters
    expect(getLatestFindingGroupResourcesMock).toHaveBeenCalledTimes(2);
    expect(getLatestFindingGroupResourcesMock).toHaveBeenNthCalledWith(1, {
      checkId: "check-1",
      page: 1,
      pageSize: 500,
      filters: {
        "filter[provider_type__in]": "aws",
        "filter[name__icontains]": "visible subset",
        "filter[status]": "FAIL",
        "filter[muted]": "false",
      },
    });
    expect(getLatestFindingGroupResourcesMock).toHaveBeenNthCalledWith(2, {
      checkId: "check-1",
      page: 2,
      pageSize: 500,
      filters: {
        "filter[provider_type__in]": "aws",
        "filter[name__icontains]": "visible subset",
        "filter[status]": "FAIL",
        "filter[muted]": "false",
      },
    });
  });

  it("deduplicates finding IDs across pages", async () => {
    // Given — same finding_id appears on both pages
    getLatestFindingGroupResourcesMock
      .mockResolvedValueOnce({
        data: [
          { id: "r-1", attributes: { finding_id: "finding-1" } },
          { id: "r-2", attributes: { finding_id: "finding-2" } },
        ],
        meta: { pagination: { pages: 2 } },
      })
      .mockResolvedValueOnce({
        data: [{ id: "r-3", attributes: { finding_id: "finding-2" } }],
        meta: { pagination: { pages: 2 } },
      });

    // When
    const result = await resolveFindingIdsByVisibleGroupResources({
      checkId: "check-1",
    });

    // Then — no duplicates
    expect(result).toEqual(["finding-1", "finding-2"]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the dated endpoint when date or scan filters are active", async () => {
    // Given
    getFindingGroupResourcesMock.mockResolvedValueOnce({
      data: [{ id: "r-1", attributes: { finding_id: "finding-1" } }],
      meta: { pagination: { pages: 1 } },
    });

    // When
    await resolveFindingIdsByVisibleGroupResources({
      checkId: "check-1",
      hasDateOrScanFilter: true,
      filters: {
        "filter[scan__in]": "scan-1",
      },
    });

    // Then — uses getFindingGroupResources (dated), not getLatestFindingGroupResources
    expect(getFindingGroupResourcesMock).toHaveBeenCalledTimes(1);
    expect(getLatestFindingGroupResourcesMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
