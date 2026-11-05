import { describe, expect, it } from "vitest";

import { calculatePercentage, cn, getOptionalText } from "@/lib/utils";

describe("cn", () => {
  it("keeps an opaque background color under a custom gradient utility", () => {
    // bg-lighthouse* set background-image, so they must not knock out a
    // background-color base — otherwise overlays turn translucent.
    expect(cn("bg-bg-neutral-tertiary bg-lighthouse-soft")).toBe(
      "bg-bg-neutral-tertiary bg-lighthouse-soft",
    );
    expect(cn("bg-bg-neutral-primary bg-lighthouse")).toBe(
      "bg-bg-neutral-primary bg-lighthouse",
    );
    expect(cn("bg-bg-neutral-primary bg-feature-cloud")).toBe(
      "bg-bg-neutral-primary bg-feature-cloud",
    );
  });

  it("still merges two conflicting gradient utilities", () => {
    expect(cn("bg-lighthouse bg-lighthouse-soft")).toBe("bg-lighthouse-soft");
  });

  it("still merges two conflicting background colors", () => {
    expect(cn("bg-bg-neutral-primary bg-bg-neutral-tertiary")).toBe(
      "bg-bg-neutral-tertiary",
    );
  });
});

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
