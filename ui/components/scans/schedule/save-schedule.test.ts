import { beforeEach, describe, expect, it, vi } from "vitest";

import { SCHEDULE_FREQUENCY, type ScheduleFormValues } from "@/types/schedules";

const { scanOnDemandMock, scheduleDailyMock, updateScheduleMock } = vi.hoisted(
  () => ({
    scanOnDemandMock: vi.fn(),
    scheduleDailyMock: vi.fn(),
    updateScheduleMock: vi.fn(),
  }),
);

vi.mock("@/actions/scans", () => ({
  scanOnDemand: scanOnDemandMock,
  scheduleDaily: scheduleDailyMock,
}));

vi.mock("@/actions/schedules", () => ({
  updateSchedule: updateScheduleMock,
}));

import {
  SAVE_SCHEDULE_STATUS,
  saveScheduleWithInitialScan,
} from "./save-schedule";

const values: ScheduleFormValues = {
  frequency: SCHEDULE_FREQUENCY.WEEKLY,
  hour: 9,
  dayOfWeek: 1,
  dayOfMonth: 1,
  intervalHours: 48,
  launchInitialScan: false,
};

describe("saveScheduleWithInitialScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    updateScheduleMock.mockResolvedValue({});
    scheduleDailyMock.mockResolvedValue({});
    scanOnDemandMock.mockResolvedValue({ data: { id: "scan-1" } });
  });

  it("saves through the schedules API with the mapped payload", async () => {
    const result = await saveScheduleWithInitialScan({
      providerId: "p1",
      values,
    });

    expect(result.status).toBe(SAVE_SCHEDULE_STATUS.SAVED);
    expect(updateScheduleMock).toHaveBeenCalledWith(
      "p1",
      expect.objectContaining({
        scan_enabled: true,
        scan_frequency: SCHEDULE_FREQUENCY.WEEKLY,
        scan_hour: 9,
        scan_day_of_week: 1,
      }),
    );
    expect(scheduleDailyMock).not.toHaveBeenCalled();
    expect(scanOnDemandMock).not.toHaveBeenCalled();
  });

  it("uses the legacy daily endpoint when requested", async () => {
    const result = await saveScheduleWithInitialScan({
      providerId: "p1",
      values,
      useLegacyDaily: true,
    });

    expect(result.status).toBe(SAVE_SCHEDULE_STATUS.SAVED);
    expect(scheduleDailyMock).toHaveBeenCalledTimes(1);
    expect(updateScheduleMock).not.toHaveBeenCalled();
  });

  it("returns an error status when the schedule save fails", async () => {
    updateScheduleMock.mockResolvedValue({ error: "boom" });

    const result = await saveScheduleWithInitialScan({
      providerId: "p1",
      values,
    });

    expect(result).toEqual({
      status: SAVE_SCHEDULE_STATUS.ERROR,
      message: "boom",
    });
    expect(scanOnDemandMock).not.toHaveBeenCalled();
  });

  it("launches the initial scan when requested", async () => {
    const result = await saveScheduleWithInitialScan({
      providerId: "p1",
      values: { ...values, launchInitialScan: true },
    });

    expect(result.status).toBe(SAVE_SCHEDULE_STATUS.SAVED_AND_LAUNCHED);
    const formData = scanOnDemandMock.mock.calls[0][0] as FormData;
    expect(formData.get("providerId")).toBe("p1");
  });

  it("reports partial success when the initial scan fails", async () => {
    scanOnDemandMock.mockResolvedValue({ error: "limit reached" });

    const result = await saveScheduleWithInitialScan({
      providerId: "p1",
      values: { ...values, launchInitialScan: true },
    });

    expect(result).toEqual({
      status: SAVE_SCHEDULE_STATUS.SAVED_SCAN_FAILED,
      message: "limit reached",
    });
  });
});
