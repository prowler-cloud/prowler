import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildProviderScheduleSummary,
  buildSchedulesByProviderId,
  buildScheduleUpdatePayload,
  formatScheduleHour,
  getBrowserTimezone,
  getNextScheduledRun,
  getScanScheduleCapability,
  getScheduleFormValues,
  isScheduleConfigured,
} from "@/lib/schedules";
import {
  SCAN_SCHEDULE_CAPABILITY,
  SCHEDULE_FREQUENCY,
  type ScheduleAttributes,
  type ScheduleProps,
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
      intervalHours: 48,
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
      intervalHours: 48,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toEqual({
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.INTERVAL,
      scan_hour: 23,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: 48,
      scan_day_of_week: null,
      scan_day_of_month: null,
    });
  });

  it("preserves a custom interval instead of rewriting it to 48 hours", () => {
    // Given a schedule whose interval was set outside the UI (e.g. bulk API)
    const values = {
      frequency: SCHEDULE_FREQUENCY.INTERVAL,
      hour: 5,
      dayOfWeek: 0,
      dayOfMonth: 1,
      intervalHours: 72,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload.scan_interval_hours).toBe(72);
  });

  it("maps weekly schedules with 0 as Sunday and clears interval/month", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.WEEKLY,
      hour: 6,
      dayOfWeek: 0,
      dayOfMonth: 28,
      intervalHours: 48,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toEqual({
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.WEEKLY,
      scan_hour: 6,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: null,
      scan_day_of_week: 0,
      scan_day_of_month: null,
    });
  });

  it("maps monthly schedules and keeps scan_hour 0 (not falsy-coerced)", () => {
    // Given
    const values = {
      frequency: SCHEDULE_FREQUENCY.MONTHLY,
      hour: 0,
      dayOfWeek: 5,
      dayOfMonth: 28,
      intervalHours: 48,
      launchInitialScan: false,
    };

    // When
    const payload = buildScheduleUpdatePayload(values);

    // Then
    expect(payload).toEqual({
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.MONTHLY,
      scan_hour: 0,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: null,
      scan_day_of_week: null,
      scan_day_of_month: 28,
    });
  });
});

describe("formatScheduleHour", () => {
  it.each([
    [0, "12:00am"],
    [12, "12:00pm"],
    [13, "1:00pm"],
    [23, "11:00pm"],
    [-1, "11:00pm"],
    [24, "12:00am"],
  ])("formats hour %i as %s", (hour, expected) => {
    expect(formatScheduleHour(hour)).toBe(expected);
  });
});

describe("isScheduleConfigured", () => {
  it("treats a null scan_hour as not configured", () => {
    expect(isScheduleConfigured({ scan_hour: null })).toBe(false);
  });

  it("treats scan_hour 0 (midnight) as configured", () => {
    expect(isScheduleConfigured({ scan_hour: 0 })).toBe(true);
  });

  it("treats a set scan_hour as configured", () => {
    expect(isScheduleConfigured({ scan_hour: 14 })).toBe(true);
  });
});

describe("getScheduleFormValues", () => {
  const buildAttributes = (
    overrides: Partial<ScheduleAttributes> = {},
  ): ScheduleAttributes => ({
    scan_enabled: true,
    scan_frequency: SCHEDULE_FREQUENCY.WEEKLY,
    scan_hour: 9,
    scan_timezone: "Europe/Madrid",
    scan_interval_hours: null,
    scan_day_of_week: 4,
    scan_day_of_month: 20,
    ...overrides,
  });

  it("returns defaults when there is no schedule", () => {
    expect(getScheduleFormValues(null)).toEqual({
      frequency: SCHEDULE_FREQUENCY.DAILY,
      hour: 0,
      dayOfWeek: 1,
      dayOfMonth: 1,
      intervalHours: 48,
      launchInitialScan: false,
    });
  });

  it("returns defaults when scan_hour is null (unconfigured provider)", () => {
    expect(getScheduleFormValues(buildAttributes({ scan_hour: null }))).toEqual(
      {
        frequency: SCHEDULE_FREQUENCY.DAILY,
        hour: 0,
        dayOfWeek: 1,
        dayOfMonth: 1,
        intervalHours: 48,
        launchInitialScan: false,
      },
    );
  });

  it("maps a configured schedule onto the form", () => {
    expect(getScheduleFormValues(buildAttributes())).toEqual({
      frequency: SCHEDULE_FREQUENCY.WEEKLY,
      hour: 9,
      dayOfWeek: 4,
      dayOfMonth: 20,
      intervalHours: 48,
      launchInitialScan: false,
    });
  });

  it("keeps a custom interval from the stored schedule", () => {
    const values = getScheduleFormValues(
      buildAttributes({
        scan_frequency: SCHEDULE_FREQUENCY.INTERVAL,
        scan_interval_hours: 72,
        scan_day_of_week: null,
        scan_day_of_month: null,
      }),
    );
    expect(values.frequency).toBe(SCHEDULE_FREQUENCY.INTERVAL);
    expect(values.intervalHours).toBe(72);
  });

  it("falls back to default day fields when the schedule leaves them null", () => {
    const values = getScheduleFormValues(
      buildAttributes({ scan_day_of_week: null, scan_day_of_month: null }),
    );
    expect(values.dayOfWeek).toBe(1);
    expect(values.dayOfMonth).toBe(1);
  });
});

describe("getNextScheduledRun", () => {
  const baseValues = {
    frequency: SCHEDULE_FREQUENCY.DAILY,
    hour: 14,
    dayOfWeek: 5,
    dayOfMonth: 15,
    intervalHours: 48,
    launchInitialScan: false,
  };
  // Wednesday 2026-06-10 10:30 local.
  const now = new Date(2026, 5, 10, 10, 30, 0, 0);

  const parts = (date: Date) => ({
    year: date.getFullYear(),
    month: date.getMonth(),
    day: date.getDate(),
    hour: date.getHours(),
  });

  it("DAILY: same day when the hour is still ahead", () => {
    expect(
      parts(getNextScheduledRun({ ...baseValues, hour: 14 }, now)),
    ).toEqual({ year: 2026, month: 5, day: 10, hour: 14 });
  });

  it("DAILY: next day when the hour already passed", () => {
    expect(parts(getNextScheduledRun({ ...baseValues, hour: 8 }, now))).toEqual(
      {
        year: 2026,
        month: 5,
        day: 11,
        hour: 8,
      },
    );
  });

  it("INTERVAL: anchors at the next occurrence of the hour, like DAILY", () => {
    // The backend derives the INTERVAL anchor as today/tomorrow at scan_hour
    // and fires the first run there; repeats only start after that.
    expect(
      parts(
        getNextScheduledRun(
          { ...baseValues, frequency: SCHEDULE_FREQUENCY.INTERVAL, hour: 14 },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 5, day: 10, hour: 14 });

    expect(
      parts(
        getNextScheduledRun(
          { ...baseValues, frequency: SCHEDULE_FREQUENCY.INTERVAL, hour: 8 },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 5, day: 11, hour: 8 });
  });

  it("WEEKLY: advances to the target weekday this week", () => {
    expect(
      parts(
        getNextScheduledRun(
          {
            ...baseValues,
            frequency: SCHEDULE_FREQUENCY.WEEKLY,
            dayOfWeek: 5,
            hour: 9,
          },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 5, day: 12, hour: 9 });
  });

  it("WEEKLY: jumps a week when the target day/hour already passed today", () => {
    expect(
      parts(
        getNextScheduledRun(
          {
            ...baseValues,
            frequency: SCHEDULE_FREQUENCY.WEEKLY,
            dayOfWeek: 3,
            hour: 8,
          },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 5, day: 17, hour: 8 });
  });

  it("MONTHLY: this month when the day is still ahead", () => {
    expect(
      parts(
        getNextScheduledRun(
          {
            ...baseValues,
            frequency: SCHEDULE_FREQUENCY.MONTHLY,
            dayOfMonth: 15,
          },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 5, day: 15, hour: 14 });
  });

  it("MONTHLY: next month when the day already passed", () => {
    expect(
      parts(
        getNextScheduledRun(
          {
            ...baseValues,
            frequency: SCHEDULE_FREQUENCY.MONTHLY,
            dayOfMonth: 5,
          },
          now,
        ),
      ),
    ).toEqual({ year: 2026, month: 6, day: 5, hour: 14 });
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

describe("buildSchedulesByProviderId", () => {
  const buildSchedule = (
    id: string,
    overrides: Partial<ScheduleAttributes> = {},
  ): ScheduleProps => ({
    type: "schedules",
    id,
    attributes: {
      scan_enabled: true,
      scan_frequency: SCHEDULE_FREQUENCY.DAILY,
      scan_hour: 9,
      scan_timezone: "Europe/Madrid",
      scan_interval_hours: null,
      scan_day_of_week: null,
      scan_day_of_month: null,
      ...overrides,
    },
    relationships: {
      provider: { data: { type: "providers", id } },
    },
  });

  it("indexes schedule attributes by provider id (the schedule's own id)", () => {
    const result = {
      data: [
        buildSchedule("provider-1", { scan_hour: 6 }),
        buildSchedule("provider-2", { scan_hour: null }),
      ],
    };

    expect(buildSchedulesByProviderId(result)).toEqual({
      "provider-1": result.data[0].attributes,
      "provider-2": result.data[1].attributes,
    });
  });

  it("returns an empty map when the request errored (e.g. OSS without /schedules)", () => {
    expect(buildSchedulesByProviderId({ error: "Not found" })).toEqual({});
  });

  it("returns an empty map for a null/undefined result", () => {
    expect(buildSchedulesByProviderId(null)).toEqual({});
    expect(buildSchedulesByProviderId(undefined)).toEqual({});
  });
});

describe("buildProviderScheduleSummary", () => {
  const buildAttributes = (
    overrides: Partial<ScheduleAttributes> = {},
  ): ScheduleAttributes => ({
    scan_enabled: true,
    scan_frequency: SCHEDULE_FREQUENCY.DAILY,
    scan_hour: 9,
    scan_timezone: "Europe/Madrid",
    scan_interval_hours: null,
    scan_day_of_week: null,
    scan_day_of_month: null,
    ...overrides,
  });

  const now = new Date(2026, 5, 10, 10, 30, 0, 0);

  it.each([
    [{ scan_frequency: SCHEDULE_FREQUENCY.DAILY }, "Daily"],
    [
      { scan_frequency: SCHEDULE_FREQUENCY.WEEKLY, scan_day_of_week: 1 },
      "Weekly on Monday",
    ],
    [
      { scan_frequency: SCHEDULE_FREQUENCY.MONTHLY, scan_day_of_month: 15 },
      "Monthly on day 15",
    ],
    [
      { scan_frequency: SCHEDULE_FREQUENCY.INTERVAL, scan_interval_hours: 72 },
      "Every 72 hours",
    ],
  ])("exposes the %o cadence as %s", (overrides, cadence) => {
    expect(
      buildProviderScheduleSummary(buildAttributes(overrides), now).cadence,
    ).toBe(cadence);
  });

  it("passes through server-computed next/last run timestamps", () => {
    const summary = buildProviderScheduleSummary(
      buildAttributes({
        next_scan_at: "2026-06-15T07:00:00Z",
        last_scan_at: "2026-06-08T07:00:00Z",
      }),
      now,
    );

    expect(summary.nextScanAt).toBe("2026-06-15T07:00:00Z");
    expect(summary.lastScanAt).toBe("2026-06-08T07:00:00Z");
  });
});
