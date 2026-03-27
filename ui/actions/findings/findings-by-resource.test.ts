import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
  appendSanitizedProviderTypeFiltersMock,
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

import { resolveFindingIdsByCheckIds } from "./findings-by-resource";

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
