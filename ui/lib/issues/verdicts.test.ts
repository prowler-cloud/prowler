import { describe, expect, it } from "vitest";

import { verdictCounts } from "@/lib/issues/verdicts";

describe("verdictCounts", () => {
  it("keeps every verdict count and drops the summary totals", () => {
    const summary = {
      exploitable: 3,
      likely: 2,
      conditional: 1,
      not_exploitable: 4,
      unknown: 5,
      issues: 15,
      findings: 40,
      actionable: 6,
    };

    expect(verdictCounts(summary)).toEqual({
      exploitable: 3,
      likely: 2,
      conditional: 1,
      not_exploitable: 4,
      unknown: 5,
    });
  });

  it("zeroes verdicts missing from a partial or absent summary", () => {
    expect(verdictCounts({ likely: 2 })).toEqual({
      exploitable: 0,
      likely: 2,
      conditional: 0,
      not_exploitable: 0,
      unknown: 0,
    });
    expect(verdictCounts(undefined)).toEqual({
      exploitable: 0,
      likely: 0,
      conditional: 0,
      not_exploitable: 0,
      unknown: 0,
    });
  });
});
