import { format, parseISO } from "date-fns";
import { describe, expect, it } from "vitest";

import { toLocalDateString } from "./date-utils";

describe("toLocalDateString", () => {
  it("returns undefined for nullish or empty input", () => {
    expect(toLocalDateString(undefined)).toBeUndefined();
    expect(toLocalDateString(null)).toBeUndefined();
    expect(toLocalDateString("")).toBeUndefined();
  });

  it("returns undefined for malformed strings", () => {
    expect(toLocalDateString("not-a-date")).toBeUndefined();
  });

  it("returns undefined for invalid Date instances", () => {
    expect(toLocalDateString(new Date("not-a-date"))).toBeUndefined();
  });

  it("formats an ISO string in the user's local timezone", () => {
    // Near UTC midnight — the UTC split ("2026-04-19") differs from the local
    // date for any tz with a positive offset. We pin parity with date-fns so
    // the assertion holds regardless of where CI runs.
    const iso = "2026-04-19T23:15:00Z";
    const expected = format(parseISO(iso), "yyyy-MM-dd");

    expect(toLocalDateString(iso)).toBe(expected);
  });

  it("formats a Date instance using its local calendar day", () => {
    const date = new Date(2026, 3, 20, 10, 0, 0); // April 20, 2026 local
    expect(toLocalDateString(date)).toBe("2026-04-20");
  });
});
