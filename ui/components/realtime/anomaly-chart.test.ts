import { describe, expect, it } from "vitest";

import { anomalyThreshold, baselineOf } from "./anomaly-chart";

describe("anomaly chart helpers", () => {
  it("needs both the ratio and the dollar increase to be crossed", () => {
    const thresholds = { min_ratio: 2, min_delta: 5 };

    expect(anomalyThreshold(10, thresholds)).toBe(20);
    expect(anomalyThreshold(1, thresholds)).toBe(6);
  });

  it("takes the baseline as the mean of the days before the last", () => {
    expect(
      baselineOf([
        { day: "a", amount: 10 },
        { day: "b", amount: 20 },
        { day: "c", amount: 100 },
      ]),
    ).toBe(15);
    expect(baselineOf([{ day: "a", amount: 10 }])).toBe(0);
    expect(baselineOf([])).toBe(0);
  });
});
