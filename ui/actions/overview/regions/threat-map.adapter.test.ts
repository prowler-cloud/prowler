import { describe, expect, it } from "vitest";

import { adaptRegionsOverviewToThreatMap } from "./threat-map.adapter";
import type { RegionsOverviewResponse } from "./types";

function buildRegionsResponse(
  rows: Array<{ providerType: string; region: string }>,
): RegionsOverviewResponse {
  return {
    data: rows.map(({ providerType, region }, index) => ({
      type: "regions-overview",
      id: `region-${index}`,
      attributes: {
        provider_type: providerType,
        region,
        total: 10,
        fail: 4,
        muted: 0,
        pass: 6,
      },
    })),
    meta: { version: "v1" },
  };
}

describe("adaptRegionsOverviewToThreatMap", () => {
  it("maps okta regions to a global location", () => {
    const response = buildRegionsResponse([
      { providerType: "okta", region: "global" },
    ]);

    const result = adaptRegionsOverviewToThreatMap(response);

    expect(result.locations).toHaveLength(1);
    expect(result.locations[0]).toMatchObject({
      providerType: "okta",
      region: "global",
      name: "Okta - Global",
      totalFindings: 10,
      failFindings: 4,
    });
    expect(result.regions).toEqual(["global"]);
  });

  it("maps googleworkspace regions to a global location", () => {
    const response = buildRegionsResponse([
      { providerType: "googleworkspace", region: "global" },
    ]);

    const result = adaptRegionsOverviewToThreatMap(response);

    expect(result.locations).toHaveLength(1);
    expect(result.locations[0]).toMatchObject({
      providerType: "googleworkspace",
      region: "global",
      name: "Google Workspace - Global",
    });
  });
});
