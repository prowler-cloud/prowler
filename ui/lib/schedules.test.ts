import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildScheduleUpdatePayload,
  getBrowserTimezone,
  getScanScheduleCapability,
} from "@/lib/schedules";
import {
  SCAN_SCHEDULE_CAPABILITY,
  SCHEDULE_FREQUENCY,
} from "@/types/schedules";

describe("schedule payload mapping", () => {
  beforeEach(() => {
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({ timeZone: "Europe/Madrid" }),
    } as Intl.DateTimeFormat);
  });

  it("maps daily schedules and clears unused fields", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.DAILY,
      hour: 8,
      dayOfWeek: 2,
      dayOfMonth: 12,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toEqual({
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.DAILY,
      scan_hour: 8,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: null,
      scan_day_of_week: null,
      scan_day_of_month: null,
    });
  });

  it("maps every 48 hours schedules as an interval", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.INTERVAL,
      hour: 23,
      dayOfWeek: 0,
      dayOfMonth: 1,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toMatchObject({
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.INTERVAL,
      scan_hour: 23,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: 48,
      scan_day_of_week: null,
      scan_day_of_month: null,
    });
  });

  it("maps weekly schedules with 0 as Sunday", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.WEEKLY,
      hour: 6,
      dayOfWeek: 0,
      dayOfMonth: 28,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toMatchObject({
      scan_frequency: SCHEDULE_FREQUENCY.WEEKLY,
      scan_day_of_week: 0,
      scan_interval_hours: null,
      scan_day_of_month: null,
    });
  });

  it("maps monthly schedules with day of month from 1 to 28", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.MONTHLY,
      hour: 0,
      dayOfWeek: 5,
      dayOfMonth: 28,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toMatchObject({
      scan_frequency: SCHEDULE_FREQUENCY.MONTHLY,
      scan_day_of_month: 28,
      scan_interval_hours: null,
      scan_day_of_week: null,
    });
  });
});

describe("browser timezone", () => {
  it("falls back to UTC when browser timezone is unavailable", () => {
    // Given
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({}),
    } as Intl.DateTimeFormat);

    // When / Then
    expect(getBrowserTimezone()).toBe("UTC");
  });
});

describe("scan schedule capability", () => {
  it("returns DAILY_LEGACY for non-Cloud (OSS)", () => {
    expect(getScanScheduleCapability(false)).toBe(
      SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY,
    );
  });

  it("returns ADVANCED for Cloud", () => {
    expect(getScanScheduleCapability(true)).toBe(
      SCAN_SCHEDULE_CAPABILITY.ADVANCED,
    );
  });
});
