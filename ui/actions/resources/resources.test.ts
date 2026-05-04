import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

// Pull every constant transitively required by the modules under test
// (resources.ts → findings action → finding-groups action) so the `@/lib`
// mock is a complete surface. Going via the barrel would drag in next-auth.
import {
  includesMutedFindings,
  splitCsvFilterValues,
} from "@/lib/findings-filters";
import {
  composeSort,
  FG_FAIL_FIRST,
  FG_RECENT_LAST_SEEN,
  FG_SEVERITY_HIGH_FIRST,
  FINDING_GROUP_RESOURCES_DEFAULT_SORT,
  FINDINGS_FILTERED_SORT,
  RESOURCE_DRAWER_OTHER_FINDINGS_SORT,
} from "@/lib/findings-sort";

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  composeSort,
  FG_FAIL_FIRST,
  FG_RECENT_LAST_SEEN,
  FG_SEVERITY_HIGH_FIRST,
  FINDING_GROUP_RESOURCES_DEFAULT_SORT,
  FINDINGS_FILTERED_SORT,
  RESOURCE_DRAWER_OTHER_FINDINGS_SORT,
  includesMutedFindings,
  splitCsvFilterValues,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("@/lib/provider-filters", () => ({
  appendSanitizedProviderTypeFilters: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

import { getResourceEvents } from "./resources";

describe("getResourceEvents", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("calls the correct API endpoint with default parameters", async () => {
    // Given
    const mockResponse = new Response("", { status: 200 });
    fetchMock.mockResolvedValue(mockResponse);
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await getResourceEvents("resource-123");

    // Then
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.pathname).toBe("/api/v1/resources/resource-123/events");
    expect(calledUrl.searchParams.get("include_read_events")).toBe("false");
    expect(calledUrl.searchParams.get("lookback_days")).toBe("90");
    expect(calledUrl.searchParams.get("page[size]")).toBe("50");
  });

  it("passes custom parameters to the API", async () => {
    // Given
    const mockResponse = new Response("", { status: 200 });
    fetchMock.mockResolvedValue(mockResponse);
    handleApiResponseMock.mockResolvedValue({ data: [] });

    // When
    await getResourceEvents("resource-456", {
      includeReadEvents: true,
      lookbackDays: 30,
      pageSize: 25,
    });

    // Then
    const calledUrl = new URL(fetchMock.mock.calls[0][0]);
    expect(calledUrl.searchParams.get("include_read_events")).toBe("true");
    expect(calledUrl.searchParams.get("lookback_days")).toBe("30");
    expect(calledUrl.searchParams.get("page[size]")).toBe("25");
  });

  it("returns parsed response on success", async () => {
    // Given
    const mockData = {
      data: [
        {
          type: "resource-events",
          id: "event-1",
          attributes: { event_name: "CreateStack" },
        },
      ],
    };
    const mockResponse = new Response("", { status: 200 });
    fetchMock.mockResolvedValue(mockResponse);
    handleApiResponseMock.mockResolvedValue(mockData);

    // When
    const result = await getResourceEvents("resource-123");

    // Then
    expect(result).toEqual(mockData);
    expect(handleApiResponseMock).toHaveBeenCalledWith(mockResponse);
  });

  it("returns error object for non-ok responses without calling handleApiResponse", async () => {
    // Given
    const errorBody = JSON.stringify({
      errors: [
        {
          detail:
            "Provider credentials are invalid or expired. Please reconnect the provider.",
        },
      ],
    });
    const mockResponse = new Response(errorBody, {
      status: 502,
      statusText: "Bad Gateway",
    });
    fetchMock.mockResolvedValue(mockResponse);

    // When
    const result = await getResourceEvents("resource-123");

    // Then
    expect(result).toEqual({
      error:
        "Provider credentials are invalid or expired. Please reconnect the provider.",
      status: 502,
    });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("returns error with statusText when response body is not JSON", async () => {
    // Given
    const mockResponse = new Response("Service Unavailable", {
      status: 503,
      statusText: "Service Unavailable",
    });
    fetchMock.mockResolvedValue(mockResponse);

    // When
    const result = await getResourceEvents("resource-123");

    // Then
    expect(result).toEqual({
      error: "Service Unavailable",
      status: 503,
    });
  });

  it("returns generic error when fetch throws", async () => {
    // Given
    fetchMock.mockRejectedValue(new Error("Network failure"));

    // When
    const result = await getResourceEvents("resource-123");

    // Then
    expect(result).toEqual({ error: "An unexpected error occurred." });
  });

  it.each([
    "../../../etc/passwd",
    "resource/../../secret",
    "id with spaces",
    "id;rm -rf /",
    "<script>alert(1)</script>",
    "resource%00id",
    "",
  ])("rejects malicious or invalid resourceId: %s", async (maliciousId) => {
    // When
    const result = await getResourceEvents(maliciousId);

    // Then
    expect(result).toEqual({ error: "Invalid resource ID format." });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
