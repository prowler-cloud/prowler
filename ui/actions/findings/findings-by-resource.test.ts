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
// Blocker 3: Muting a group mutes ALL historical findings, not just FAIL ones
//
// The fix: resolveFindingIds must include filter[status]=FAIL so only active
// (failing) findings are resolved for mute, not historical/passing ones.
// ---------------------------------------------------------------------------

describe("resolveFindingIds — Blocker 3: only resolve FAIL findings for mute", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("should include filter[status]=FAIL in the findings resolution URL for mute", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }, { id: "finding-2" }],
    });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids: ["resource-1", "resource-2"],
    });

    // Then — the URL must filter to only FAIL status findings
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.searchParams.get("filter[status]")).toBe("FAIL");
  });

  it("should include filter[status]=FAIL even when date or scan filters are active", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }],
    });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids: ["resource-1"],
      hasDateOrScanFilter: true,
      filters: {
        "filter[inserted_at__gte]": "2026-01-01",
      },
    });

    // Then
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.pathname).toBe("/api/v1/findings");
    expect(calledUrl.searchParams.get("filter[status]")).toBe("FAIL");
  });

  it("should override caller filter[status] with FAIL — no duplicate params", async () => {
    // Given — caller passes filter[status]=PASS via filters dict
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({
      data: [{ id: "finding-1" }],
    });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids: ["resource-1"],
      filters: {
        "filter[status]": "PASS",
      },
    });

    // Then — hardcoded FAIL must win, exactly 1 value
    const calledUrl = new URL(fetchMock.mock.calls[0][0] as string);
    const statusValues = calledUrl.searchParams.getAll("filter[status]");
    expect(statusValues).toHaveLength(1);
    expect(statusValues[0]).toBe("FAIL");
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

  it("keeps every request page[size] at or below 500 when resolving a 500-UID batch", async () => {
    // Given — exactly 500 unique UIDs. The resolver may split earlier than 500
    // to keep the resource_uid__in query string at a safe size.
    const resourceUids = Array.from({ length: 500 }, (_, i) => `resource-${i}`);
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids,
    });

    // Then — every request must stay under the defensive cap and preserve FAIL filtering
    const pageSizes = fetchMock.mock.calls.map(
      ([url]) => Number(new URL(url as string).searchParams.get("page[size]")),
    );
    expect(pageSizes.every((pageSize) => pageSize > 0 && pageSize <= 500)).toBe(
      true,
    );
    expect(pageSizes.reduce((sum, pageSize) => sum + pageSize, 0)).toBe(500);
  });

  it("keeps every request page[size] at or below 500 when resolving more than 500 UIDs", async () => {
    // Given — 501 UIDs. The resolver can split by count and/or URL length,
    // but no request may exceed the page-size cap.
    const resourceUids = Array.from({ length: 501 }, (_, i) => `resource-${i}`);
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids,
    });

    // Then
    const pageSizes = fetchMock.mock.calls.map(
      ([url]) => Number(new URL(url as string).searchParams.get("page[size]")),
    );
    expect(pageSizes.every((pageSize) => pageSize > 0 && pageSize <= 500)).toBe(
      true,
    );
    expect(pageSizes.reduce((sum, pageSize) => sum + pageSize, 0)).toBe(501);
  });

  it("splits long resource UID batches into multiple requests before the URL becomes too large", async () => {
    // Given — 100 long UIDs would fit under the 500-count cap but produce
    // an oversized resource_uid__in query string if sent in a single request.
    const resourceUids = Array.from(
      { length: 100 },
      (_, i) => `arn:aws:ec2:eu-west-1:123456789012:instance/i-${`${i}`.padStart(17, "0")}`,
    );
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "check-1",
      resourceUids,
    });

    // Then
    expect(fetchMock.mock.calls.length).toBeGreaterThan(1);
    const firstUrl = new URL(fetchMock.mock.calls[0][0] as string);
    expect(firstUrl.searchParams.get("page[size]")).not.toBe("100");
  });

  it("keeps each resolution request URL under the safe maximum for long ECS task definition ARNs", async () => {
    // Given — these ARNs match the failing production shape closely enough to
    // reproduce the oversized query-string bug.
    const resourceUids = Array.from(
      { length: 120 },
      (_, i) =>
        `arn:aws:ecs:eu-west-1:106908755756:task-definition/prowler-cloud-dev-workers:${500 - i}`,
    );
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await resolveFindingIds({
      checkId: "ecs_task_definitions_no_environment_secrets",
      resourceUids,
      filters: {
        "filter[status__in]": "FAIL",
        "filter[muted]": "false",
      },
    });

    // Then — every backend request must stay comfortably below common proxy
    // limits for the full URL, not just the raw CSV length.
    const requestUrls = fetchMock.mock.calls.map(([url]) => String(url));
    expect(requestUrls.length).toBeGreaterThan(1);
    expect(requestUrls.every((url) => url.length <= 3800)).toBe(true);
  });
});
