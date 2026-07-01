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

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  GENERIC_SERVER_ERROR_MESSAGE:
    "Server is temporarily unavailable. Please try again in a few minutes.",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("@/lib/sentry-breadcrumbs", () => ({
  addScanOperation: vi.fn(),
}));

import { getExportsZip, launchOrganizationScans } from "./scans";

describe("launchOrganizationScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: { id: "scan-id" } });
    handleApiErrorMock.mockReturnValue({ error: "Scan launch failed." });
  });

  it("limits concurrent launch requests to avoid overwhelming the backend", async () => {
    // Given
    const providerIds = Array.from(
      { length: 12 },
      (_, index) => `provider-${index + 1}`,
    );
    let activeRequests = 0;
    let maxActiveRequests = 0;

    fetchMock.mockImplementation(async () => {
      activeRequests += 1;
      maxActiveRequests = Math.max(maxActiveRequests, activeRequests);
      await new Promise((resolve) => setTimeout(resolve, 5));
      activeRequests -= 1;

      return new Response(JSON.stringify({ data: { id: "scan-id" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    // When
    const result = await launchOrganizationScans(providerIds, "daily");

    // Then
    expect(maxActiveRequests).toBeLessThanOrEqual(5);
    expect(result.successCount).toBe(providerIds.length);
    expect(result.failureCount).toBe(0);
  });
});

describe("getExportsZip", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("returns a generic server error when the report endpoint returns HTML", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(
        "<html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>",
        {
          status: 502,
          statusText: "Bad Gateway",
          headers: { "content-type": "text/html" },
        },
      ),
    );

    // When
    const result = await getExportsZip("scan-123");

    // Then
    expect(result).toEqual({
      error:
        "Server is temporarily unavailable. Please try again in a few minutes.",
    });
  });
});
