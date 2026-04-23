import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type AttackPathScan,
  type AttackPathScansResponse,
  SCAN_STATES,
} from "@/types/attack-paths";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { getAttackPathScans } from "./scans";

const makeScan = (id: string): AttackPathScan => ({
  type: "attack-paths-scans",
  id,
  attributes: {
    state: SCAN_STATES.COMPLETED,
    progress: 100,
    graph_data_ready: true,
    provider_alias: `alias-${id}`,
    provider_type: "aws",
    provider_uid: id,
    inserted_at: "2026-04-23T10:00:00Z",
    started_at: "2026-04-23T10:00:00Z",
    completed_at: "2026-04-23T10:10:00Z",
    duration: 600,
  },
  relationships: {} as AttackPathScan["relationships"],
});

const pageResponse = (
  ids: string[],
  page: number,
  pages: number,
  count: number,
): AttackPathScansResponse => ({
  data: ids.map(makeScan),
  links: {
    first: "first",
    last: "last",
    next: page < pages ? "next" : null,
    prev: page > 1 ? "prev" : null,
  },
  meta: {
    pagination: { page, pages, count },
  },
});

const getFetchedPageNumber = (call: unknown[]) => {
  const url = new URL(String(call[0]));
  return Number(url.searchParams.get("page[number]"));
};

describe("getAttackPathScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("requests page[size]=100 with page[number]=1 on the first call", async () => {
    // Given
    handleApiResponseMock.mockResolvedValueOnce(pageResponse(["s1"], 1, 1, 1));

    // When
    await getAttackPathScans();

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    const url = new URL(String(call[0]));
    expect(url.pathname).toBe("/api/v1/attack-paths-scans");
    expect(url.searchParams.get("page[number]")).toBe("1");
    expect(url.searchParams.get("page[size]")).toBe("100");
  });

  it("iterates across every backend page and aggregates all scans", async () => {
    // Given three pages totalling 22 scans
    handleApiResponseMock
      .mockResolvedValueOnce(
        pageResponse(
          Array.from({ length: 10 }, (_, i) => `a${i}`),
          1,
          3,
          22,
        ),
      )
      .mockResolvedValueOnce(
        pageResponse(
          Array.from({ length: 10 }, (_, i) => `b${i}`),
          2,
          3,
          22,
        ),
      )
      .mockResolvedValueOnce(pageResponse(["c0", "c1"], 3, 3, 22));

    // When
    const result = await getAttackPathScans();

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls.map(getFetchedPageNumber)).toEqual([1, 2, 3]);
    expect(result?.data).toHaveLength(22);
  });

  it("stops requesting when the current page equals meta.pagination.pages", async () => {
    // Given a single-page response
    handleApiResponseMock.mockResolvedValueOnce(
      pageResponse(["only"], 1, 1, 1),
    );

    // When
    const result = await getAttackPathScans();

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result?.data).toHaveLength(1);
  });

  it("stops when a page returns an empty data array", async () => {
    // Given the second page is unexpectedly empty
    handleApiResponseMock
      .mockResolvedValueOnce(pageResponse(["a0"], 1, 3, 3))
      .mockResolvedValueOnce({
        data: [],
        links: { first: "", last: "", next: null, prev: null },
        meta: { pagination: { page: 2, pages: 3, count: 3 } },
      } as AttackPathScansResponse);

    // When
    const result = await getAttackPathScans();

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result?.data).toHaveLength(1);
  });

  it("returns undefined when the first fetch throws", async () => {
    // Given
    handleApiResponseMock.mockRejectedValueOnce(new Error("network down"));

    // When
    const result = await getAttackPathScans();

    // Then
    expect(result).toBeUndefined();
  });

  it("returns an empty list when the first page has no data", async () => {
    // Given
    handleApiResponseMock.mockResolvedValueOnce(undefined);

    // When
    const result = await getAttackPathScans();

    // Then
    expect(result).toEqual({ data: [] });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
