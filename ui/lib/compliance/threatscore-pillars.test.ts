import { describe, expect, it } from "vitest";

import {
  compareSectionsByCanonicalOrder,
  getOrderedPillars,
  THREATSCORE_PILLARS,
} from "./threatscore-pillars";

describe("getOrderedPillars", () => {
  it("returns every canonical pillar in canonical order even when some are missing", () => {
    const result = getOrderedPillars({ "1. IAM": 90, "4. Encryption": 60 });

    expect(result.map((p) => p.name)).toEqual([...THREATSCORE_PILLARS]);
    expect(result[0]).toEqual({ name: "1. IAM", score: 90, hasData: true });
    expect(result[1]).toEqual({
      name: "2. Attack Surface",
      score: 0,
      hasData: false,
    });
    expect(result[3]).toEqual({
      name: "4. Encryption",
      score: 60,
      hasData: true,
    });
  });

  it("appends non-canonical sections after the canonical ones, sorted naturally", () => {
    const result = getOrderedPillars({
      "1. IAM": 50,
      "10. Future Pillar": 70,
      "5. Data Protection": 80,
    });

    expect(result.map((p) => p.name)).toEqual([
      "1. IAM",
      "2. Attack Surface",
      "3. Logging and Monitoring",
      "4. Encryption",
      "5. Data Protection",
      "10. Future Pillar",
    ]);
  });

  it("handles undefined sectionScores gracefully", () => {
    const result = getOrderedPillars(undefined);

    expect(result).toHaveLength(THREATSCORE_PILLARS.length);
    expect(result.every((p) => !p.hasData)).toBe(true);
  });

  it("treats non-numeric or non-finite scores as missing data", () => {
    // Defensive: API contract is Record<string, number>, but null/string/NaN
    // should never crash a `score.toFixed(...)` consumer.
    const result = getOrderedPillars({
      "1. IAM": Number.NaN as unknown as number,
      "2. Attack Surface": null as unknown as number,
      "3. Logging and Monitoring": "80" as unknown as number,
      "4. Encryption": 60,
    });

    expect(result[0]).toEqual({ name: "1. IAM", score: 0, hasData: false });
    expect(result[1]).toEqual({
      name: "2. Attack Surface",
      score: 0,
      hasData: false,
    });
    expect(result[2]).toEqual({
      name: "3. Logging and Monitoring",
      score: 0,
      hasData: false,
    });
    expect(result[3]).toEqual({
      name: "4. Encryption",
      score: 60,
      hasData: true,
    });
  });
});

describe("compareSectionsByCanonicalOrder", () => {
  it("orders canonical pillars by their declared position", () => {
    const sections = [
      "4. Encryption",
      "2. Attack Surface",
      "1. IAM",
      "3. Logging and Monitoring",
    ];
    sections.sort(compareSectionsByCanonicalOrder);
    expect(sections).toEqual([...THREATSCORE_PILLARS]);
  });

  it("places unknown sections after canonical ones, in natural order", () => {
    const sections = [
      "Custom Section",
      "10. Tenth",
      "1. IAM",
      "5. Data Protection",
    ];
    sections.sort(compareSectionsByCanonicalOrder);
    expect(sections).toEqual([
      "1. IAM",
      "5. Data Protection",
      "10. Tenth",
      "Custom Section",
    ]);
  });
});
