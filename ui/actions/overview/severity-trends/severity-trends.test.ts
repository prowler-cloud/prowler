import { beforeEach, describe, expect, it, vi } from "vitest";

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

import { getFindingsSeverityTrends } from "./severity-trends";

describe("getFindingsSeverityTrends", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("returns an error status on a 4xx response shape", async () => {
    // handleApiResponse resolves truthy {error, status} objects for 4xx.
    handleApiResponseMock.mockResolvedValueOnce({
      error: "Invalid filter",
      status: 400,
    });

    const result = await getFindingsSeverityTrends();

    expect(result).toEqual({ status: "error" });
  });

  it("returns an empty status on a no-content response shape", async () => {
    // handleApiResponse resolves {success, status} for 204 and empty bodies.
    handleApiResponseMock.mockResolvedValueOnce({
      success: true,
      status: 204,
    });

    const result = await getFindingsSeverityTrends();

    expect(result).toEqual({ status: "empty" });
  });

  it("returns an empty status when the trend list has no entries", async () => {
    handleApiResponseMock.mockResolvedValueOnce({ data: [] });

    const result = await getFindingsSeverityTrends();

    expect(result).toEqual({ status: "empty" });
  });
});
