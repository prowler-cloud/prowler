import { beforeEach, describe, expect, it, vi } from "vitest";

import { SCHEDULE_FREQUENCY } from "@/types/schedules";

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
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiError: handleApiErrorMock,
  handleApiResponse: handleApiResponseMock,
}));

import { getSchedule, removeSchedule, updateSchedule } from "./schedules";

describe("schedule actions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    handleApiResponseMock.mockResolvedValue({ success: true });
    handleApiErrorMock.mockReturnValue({ error: "Failed" });
  });

  it("fetches a provider schedule with provider include", async () => {
    // Given
    const providerId = "provider-1";

    // When
    await getSchedule(providerId);

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/schedules/provider-1?include=provider",
      { headers: { Authorization: "Bearer token" } },
    );
  });

  it("patches schedule attributes through the new provider schedule endpoint", async () => {
    // Given
    const payload = {
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.DAILY,
      scan_hour: 12,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: null,
      scan_day_of_week: null,
      scan_day_of_month: null,
    };

    // When
    await updateSchedule("provider-1", payload);

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/schedules/provider-1",
      expect.objectContaining({
        method: "PATCH",
        headers: { Authorization: "Bearer token" },
        body: JSON.stringify({
          data: {
            type: "schedules",
            id: "provider-1",
            attributes: payload,
          },
        }),
      }),
    );
  });

  it("removes schedules through DELETE /schedules/{providerId}", async () => {
    // Given / When
    await removeSchedule("provider-1");

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/schedules/provider-1",
      expect.objectContaining({
        method: "DELETE",
        headers: { Authorization: "Bearer token" },
      }),
    );
  });
});
