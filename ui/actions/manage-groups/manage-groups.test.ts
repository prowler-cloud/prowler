import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: vi.fn(),
}));

vi.mock("@/lib/auth-headers", () => ({
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import { getAllProviderGroups } from "./manage-groups";

const makeGroup = (id: string, name: string) => ({
  type: "provider-groups" as const,
  id,
  attributes: { name, inserted_at: "", updated_at: "" },
  relationships: {
    providers: { meta: { count: 0 }, data: [] },
    roles: { meta: { count: 0 }, data: [] },
  },
  links: { self: "" },
});

const makePage = (
  data: ReturnType<typeof makeGroup>[],
  page: number,
  pages: number,
) => ({
  links: { first: "", last: "", next: null, prev: null },
  data,
  meta: { pagination: { page, pages, count: data.length } },
});

describe("getAllProviderGroups", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("merges every page into a single response with collapsed pagination", async () => {
    handleApiResponseMock
      .mockResolvedValueOnce(
        makePage(
          [makeGroup("g1", "Group 1"), makeGroup("g2", "Group 2")],
          1,
          2,
        ),
      )
      .mockResolvedValueOnce(makePage([makeGroup("g3", "Group 3")], 2, 2));

    const result = await getAllProviderGroups();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result?.data.map((group) => group.id)).toEqual(["g1", "g2", "g3"]);
    expect(result?.meta.pagination).toMatchObject({
      page: 1,
      pages: 1,
      count: 3,
    });
  });

  it("stops after the first page when there is only one page", async () => {
    handleApiResponseMock.mockResolvedValueOnce(
      makePage([makeGroup("g1", "Group 1")], 1, 1),
    );

    const result = await getAllProviderGroups();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result?.data).toHaveLength(1);
  });

  it("returns undefined when the first page has no data", async () => {
    handleApiResponseMock.mockResolvedValueOnce(makePage([], 1, 1));

    const result = await getAllProviderGroups();

    expect(result).toBeUndefined();
  });

  it("returns undefined when the request throws", async () => {
    fetchMock.mockRejectedValueOnce(new Error("network down"));

    const result = await getAllProviderGroups();

    expect(result).toBeUndefined();
  });

  it("rethrows the framework redirect from authentication", async () => {
    // Given
    const redirectError = new Error("NEXT_REDIRECT");
    getAuthHeadersMock.mockRejectedValueOnce(redirectError);

    // When / Then
    await expect(getAllProviderGroups()).rejects.toBe(redirectError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns undefined when a later page resolves to an error payload", async () => {
    handleApiResponseMock
      .mockResolvedValueOnce(makePage([makeGroup("g1", "Group 1")], 1, 2))
      .mockResolvedValueOnce({ error: "Forbidden", status: 403 });

    const result = await getAllProviderGroups();

    expect(result).toBeUndefined();
  });

  it("returns undefined instead of a truncated list when the max-page cap is hit", async () => {
    // Given an API that always reports more pages than the 50-page safety cap
    handleApiResponseMock.mockImplementation((response: Response) => {
      void response;
      return Promise.resolve(makePage([makeGroup("g", "Group")], 1, 9999));
    });

    // When fetching every page
    const result = await getAllProviderGroups();

    // Then it must not return a partial/truncated list; bail out instead
    expect(result).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(50);
  });
});
