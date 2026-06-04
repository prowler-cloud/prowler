import { describe, expect, it, vi } from "vitest";

import {
  buildScheduleUpdatePayload,
  getBrowserTimezone,
  getScheduleFormDefaults,
} from "@/lib/schedules";
import { SCHEDULE_FREQUENCY } from "@/types/schedules";

describe("schedule payload mapping", () => {
  it("maps daily schedules and clears unused fields", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.DAILY,
      hour: 8,
      timezone: "Europe/Madrid",
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
      timezone: "UTC",
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
      timezone: "America/New_York",
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
      timezone: "UTC",
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

describe("schedule defaults", () => {
  it("uses the browser timezone as the default timezone", () => {
    // Given
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({ timeZone: "Europe/Madrid" }),
    } as Intl.DateTimeFormat);

    // When
    const defaults = getScheduleFormDefaults();

    // Then
    expect(defaults.timezone).toBe("Europe/Madrid");
  });

  it("falls back to UTC when browser timezone is unavailable", () => {
    // Given
    vi.spyOn(Intl, "DateTimeFormat").mockReturnValue({
      resolvedOptions: () => ({}),
    } as Intl.DateTimeFormat);

    // When / Then
    expect(getBrowserTimezone()).toBe("UTC");
  });
});
