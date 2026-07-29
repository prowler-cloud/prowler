import { describe, expect, it } from "vitest";

import { getSankeyLayoutConfig } from "./sankey-chart.layout";

describe("getSankeyLayoutConfig", () => {
  it("keeps default size when provider count is at baseline", () => {
    const config = getSankeyLayoutConfig({
      baseHeight: 460,
      nodes: [
        { name: "AWS" },
        { name: "High" },
        { name: "Medium" },
        { name: "Low" },
        { name: "Azure" },
        { name: "Info" },
        { name: "GCP" },
      ],
      links: [{ source: 0 }, { source: 4 }, { source: 6 }],
    });

    expect(config).toEqual({
      height: 460,
      nodePadding: 50,
    });
  });

  it("increases height and reduces node padding for denser graphs", () => {
    const config = getSankeyLayoutConfig({
      baseHeight: 460,
      nodes: Array.from({ length: 24 }, (_, index) => ({
        name: `Provider ${index}`,
      })),
      links: [
        { source: 0 },
        { source: 1 },
        { source: 2 },
        { source: 3 },
        { source: 4 },
        { source: 5 },
        { source: 6 },
        { source: 7 },
        { source: 8 },
        { source: 9 },
        { source: 10 },
        { source: 11 },
      ],
    });

    expect(config).toEqual({
      height: 844,
      nodePadding: 38,
    });
  });

  it("clamps padding to minimum when provider count is very large", () => {
    const config = getSankeyLayoutConfig({
      baseHeight: 460,
      nodes: Array.from({ length: 120 }, (_, index) => ({
        name: `Provider ${index}`,
      })),
      links: Array.from({ length: 100 }, (_, index) => ({
        source: index,
      })),
    });

    expect(config.nodePadding).toBe(14);
    expect(config.height).toBe(1400);
  });

  it("falls back to node-based provider estimation when no link sources exist", () => {
    const config = getSankeyLayoutConfig({
      baseHeight: 460,
      nodes: Array.from({ length: 8 }, (_, index) => ({
        name: `Node ${index}`,
      })),
      links: [],
    });

    expect(config).toEqual({
      height: 460,
      nodePadding: 50,
    });
  });
});
