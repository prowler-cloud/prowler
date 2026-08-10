import { describe, expect, it } from "vitest";

import {
  GRAPH_ALERT_BORDER_COLOR,
  GRAPH_EDGE_HIGHLIGHT_COLOR,
  GRAPH_NODE_COLORS,
  GRAPH_OUTCOME_BORDER_COLOR,
  GRAPH_OUTCOME_FILL_COLOR,
  resolveNodeColors,
} from "./graph-colors";
import {
  GROUP_NODE_LABEL,
  GROUP_PROPS,
  OUTCOME_NODE_LABEL,
} from "./group-graph";

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

  it("uses the synthetic node palettes", () => {
    // Given
    const properties = {
      [GROUP_PROPS.CLASS]: "IAMRole",
      [GROUP_PROPS.HAS_FINDINGS]: true,
    };

    // When
    const groupColors = resolveNodeColors({
      labels: [GROUP_NODE_LABEL],
      properties,
    });
    const outcomeColors = resolveNodeColors({ labels: [OUTCOME_NODE_LABEL] });

    // Then
    expect(groupColors).toEqual({
      fillColor: GRAPH_NODE_COLORS.iamRole,
      borderColor: GRAPH_ALERT_BORDER_COLOR,
    });
    expect(outcomeColors).toEqual({
      fillColor: GRAPH_OUTCOME_FILL_COLOR,
      borderColor: GRAPH_OUTCOME_BORDER_COLOR,
    });
  });
});
