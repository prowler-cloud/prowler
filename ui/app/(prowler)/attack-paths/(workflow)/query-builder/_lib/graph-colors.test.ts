import { describe, expect, it } from "vitest";

import {
  GRAPH_ALERT_BORDER_COLOR,
  GRAPH_EDGE_HIGHLIGHT_COLOR,
  resolveNodeColors,
} from "./graph-colors";

describe("resolveNodeColors", () => {
  it("prioritizes selected state over hasFindings for the border color", () => {
    const selectedColors = resolveNodeColors({
      labels: ["EC2Instance"],
      selected: true,
      hasFindings: true,
    });

    const alertOnlyColors = resolveNodeColors({
      labels: ["EC2Instance"],
      selected: false,
      hasFindings: true,
    });

    expect(selectedColors.borderColor).toBe(GRAPH_EDGE_HIGHLIGHT_COLOR);
    expect(alertOnlyColors.borderColor).toBe(GRAPH_ALERT_BORDER_COLOR);
  });
});
