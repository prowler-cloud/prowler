import { beforeEach, describe, expect, it, vi } from "vitest";

import { SCHEDULE_FREQUENCY } from "@/types/schedules";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiErrorMock,
  handleApiResponseMock,
  revalidatePathMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiErrorMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  revalidatePathMock: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: revalidatePathMock,
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

const PROVIDER_ID = "1795f636-37e6-42f6-b158-d4faaa64e0fc";

const payload = {
  scan_enabled: true,
  scan_frequency: SCHEDULE_FREQUENCY.DAILY,
  scan_hour: 12,
  scan_timezone: "Europe/Madrid",
  scan_interval_hours: null,
  scan_day_of_week: null,
  scan_day_of_month: null,
};

describe("schedule write actions revalidate only on success", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    handleApiErrorMock.mockReturnValue({ error: "Failed" });
  });

  it("revalidates /scans and /providers after a successful update", async () => {
    handleApiResponseMock.mockResolvedValue({ success: true });

    await updateSchedule(PROVIDER_ID, payload);

    expect(revalidatePathMock).toHaveBeenCalledWith("/scans");
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("does not revalidate when the update returns an error result", async () => {
    handleApiResponseMock.mockResolvedValue({ error: "Schedule rejected" });

    await updateSchedule(PROVIDER_ID, payload);

    expect(revalidatePathMock).not.toHaveBeenCalled();
  });

  it("revalidates /scans and /providers after a successful delete", async () => {
    handleApiResponseMock.mockResolvedValue({ success: true });

    await removeSchedule(PROVIDER_ID);

    expect(revalidatePathMock).toHaveBeenCalledWith("/scans");
    expect(revalidatePathMock).toHaveBeenCalledWith("/providers");
  });

  it("does not revalidate when the delete returns an error result", async () => {
    handleApiResponseMock.mockResolvedValue({ error: "Not allowed" });

    await removeSchedule(PROVIDER_ID);

    expect(revalidatePathMock).not.toHaveBeenCalled();
  });

  it("rejects non-UUID provider ids without issuing a request", async () => {
    const malicious = "../users/me";

    expect(await getSchedule(malicious)).toEqual({
      error: "Invalid provider id.",
    });
    expect(await updateSchedule(malicious, payload)).toEqual({
      error: "Invalid provider id.",
    });
    expect(await removeSchedule(malicious)).toEqual({
      error: "Invalid provider id.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
