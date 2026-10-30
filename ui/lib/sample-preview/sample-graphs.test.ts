import { describe, expect, it } from "vitest";

import {
  SAMPLE_NEW_FINDINGS,
  SAMPLE_RISK_PLOT_POINTS,
  SAMPLE_SANKEY_DATA,
  SAMPLE_THREAT_MAP_DATA,
} from "./sample-graphs";
import { SAMPLE_STATUS } from "./sample-overview";

describe("sample graphs", () => {
  it("agrees with the Overview failed and new totals", () => {
    const sum = (values: number[]) => values.reduce((a, b) => a + b, 0);

    expect(
      sum(SAMPLE_THREAT_MAP_DATA.locations.map((l) => l.failFindings)),
    ).toBe(SAMPLE_STATUS.fail);
    expect(
      sum(SAMPLE_THREAT_MAP_DATA.locations.map((l) => l.totalFindings)),
    ).toBe(SAMPLE_STATUS.fail + SAMPLE_STATUS.pass);
    expect(sum(SAMPLE_SANKEY_DATA.links.map((link) => link.value))).toBe(
      SAMPLE_STATUS.fail,
    );
    expect(SAMPLE_RISK_PLOT_POINTS[0].y).toBe(SAMPLE_STATUS.fail);
    expect(SAMPLE_NEW_FINDINGS).toHaveLength(
      Math.min(SAMPLE_STATUS.failNew, 10),
    );
  });
});
