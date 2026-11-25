import { afterEach, describe, expect, it, vi } from "vitest";

import {
  defaultPostureChangePeriod,
  POSTURE_CHANGE_MAX_DAYS,
  utcToday,
  validatePostureChangePeriod,
} from "./posture-change-period";

const TODAY = new Date(2026, 2, 31, 15, 30);
const day = (month: number, date: number) => new Date(2026, month, date);

describe("validatePostureChangePeriod", () => {
  it("returns API dates for a valid period", () => {
    expect(
      validatePostureChangePeriod({ from: day(2, 1), to: day(2, 31) }, TODAY),
    ).toEqual({ dateFrom: "2026-03-01", dateTo: "2026-03-31" });
  });

  it("accepts a single day", () => {
    expect(
      validatePostureChangePeriod({ from: day(2, 5), to: day(2, 5) }, TODAY),
    ).toEqual({ dateFrom: "2026-03-05", dateTo: "2026-03-05" });
  });

  it("requires both ends of the range", () => {
    expect(validatePostureChangePeriod({ from: day(2, 1) }, TODAY)).toEqual({
      error: "Select a start and an end date.",
    });
  });

  it("rejects an end date in the future", () => {
    expect(
      validatePostureChangePeriod({ from: day(2, 1), to: day(3, 1) }, TODAY),
    ).toHaveProperty("error");
  });

  it("rejects a period longer than the API cap", () => {
    const from = new Date(2026, 2, 31 - POSTURE_CHANGE_MAX_DAYS);
    expect(
      validatePostureChangePeriod({ from, to: day(2, 31) }, TODAY),
    ).toHaveProperty("error");
    const longest = new Date(2026, 2, 32 - POSTURE_CHANGE_MAX_DAYS);
    expect(
      validatePostureChangePeriod({ from: longest, to: day(2, 31) }, TODAY),
    ).not.toHaveProperty("error");
  });
});

describe("defaultPostureChangePeriod", () => {
  it("covers the last 30 days and is always valid", () => {
    const period = defaultPostureChangePeriod(TODAY);
    expect(validatePostureChangePeriod(period, TODAY)).toEqual({
      dateFrom: "2026-03-02",
      dateTo: "2026-03-31",
    });
  });
});

describe("utcToday", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("uses the UTC calendar day, not the local one", () => {
    vi.stubEnv("TZ", "Pacific/Kiritimati");
    const now = new Date(Date.UTC(2026, 10, 25, 23, 30));
    const today = utcToday(now);
    expect([today.getFullYear(), today.getMonth(), today.getDate()]).toEqual([
      2026, 10, 25,
    ]);
  });
});
