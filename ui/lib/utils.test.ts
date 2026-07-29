import { describe, expect, it } from "vitest";

import { calculatePercentage, getOptionalText } from "@/lib/utils";

describe("calculatePercentage", () => {
  it("rounds the percentage to the nearest integer", () => {
    expect(calculatePercentage(1, 3)).toBe(33);
    expect(calculatePercentage(2, 3)).toBe(67);
  });

  it("returns 0 when the total is 0", () => {
    expect(calculatePercentage(5, 0)).toBe(0);
  });
});

describe("getOptionalText", () => {
  it("returns the string when it has usable content", () => {
    expect(getOptionalText("my-resource")).toBe("my-resource");
  });

  it("returns undefined for the '-' placeholder", () => {
    expect(getOptionalText("-")).toBeUndefined();
  });

  it("returns undefined for empty or whitespace-only strings", () => {
    expect(getOptionalText("")).toBeUndefined();
    expect(getOptionalText("   ")).toBeUndefined();
  });

  it("returns undefined for non-string values", () => {
    expect(getOptionalText(undefined)).toBeUndefined();
    expect(getOptionalText(null)).toBeUndefined();
    expect(getOptionalText(42)).toBeUndefined();
  });
});
