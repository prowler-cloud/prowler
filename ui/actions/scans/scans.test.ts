import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  addScanOperationMock,
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  addScanOperationMock: vi.fn(),
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
  addScanOperation: addScanOperationMock,
}));

import {
  getExportsZip,
  launchOrganizationScans,
  scheduleOrganizationDailyScans,
} from "./scans";

describe("launchOrganizationScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [{ id: "scan-1" }] });
  });

  it("sends one organization bulk scan request", async () => {
    // Given
    const scans = [
      { id: "scan-1", type: "scans" },
      { id: "scan-2", type: "scans" },
    ];
    fetchMock.mockResolvedValue(new Response(null, { status: 202 }));
    handleApiResponseMock.mockResolvedValue({ data: scans });

    // When
    const result = await launchOrganizationScans("organization-1");

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/scans/bulk",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          data: {
            type: "scans-bulk",
            relationships: {
              organization: {
                data: {
                  type: "organizations",
                  id: "organization-1",
                },
              },
            },
          },
        }),
      }),
    );
    expect(handleApiResponseMock).toHaveBeenCalledWith(
      expect.any(Response),
      "/scans",
    );
    expect(result).toEqual({ data: scans });
    expect(addScanOperationMock).toHaveBeenCalledTimes(1);
    expect(addScanOperationMock).toHaveBeenCalledWith("start", undefined, {
      organization_id: "organization-1",
      bulk: true,
      scan_count: 2,
      scan_ids: "scan-1,scan-2",
    });
  });

  it("rejects a successful response without a scan collection", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response(null, { status: 202 }));
    handleApiResponseMock.mockResolvedValue({
      data: { id: "scan-1", type: "scans" },
    });

    // When
    const result = await launchOrganizationScans("organization-1");

    // Then
    expect(result).toEqual({
      error: "The bulk scan response did not contain a scan collection.",
    });
    expect(addScanOperationMock).not.toHaveBeenCalled();
  });
});

describe("scheduleOrganizationDailyScans", () => {
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
    const result = await scheduleOrganizationDailyScans(providerIds);

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
