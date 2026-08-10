import { describe, expect, it } from "vitest";

import {
  GRAPH_ALERT_BORDER_COLOR,
  GRAPH_EDGE_HIGHLIGHT_COLOR,
  GRAPH_NODE_COLORS,
  GRAPH_OUTCOME_BORDER_COLOR,
  GRAPH_OUTCOME_FILL_COLOR,
  getNodeBorderColor,
  getNodeColor,
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

  it("uses the represented resource class for a group node", () => {
    const properties = {
      [GROUP_PROPS.CLASS]: "IAMRole",
      [GROUP_PROPS.HAS_FINDINGS]: false,
    };

    expect(getNodeColor([GROUP_NODE_LABEL], properties)).toBe(
      GRAPH_NODE_COLORS.iamRole,
    );
  });

  it("keeps the finding alert border on a collapsed group", () => {
    const properties = {
      [GROUP_PROPS.CLASS]: "IAMRole",
      [GROUP_PROPS.HAS_FINDINGS]: true,
    };

    expect(getNodeBorderColor([GROUP_NODE_LABEL], properties)).toBe(
      GRAPH_ALERT_BORDER_COLOR,
    );
  });

  it("uses the dedicated outcome palette for an outcome node", () => {
    expect(getNodeColor([OUTCOME_NODE_LABEL])).toBe(GRAPH_OUTCOME_FILL_COLOR);
    expect(getNodeBorderColor([OUTCOME_NODE_LABEL])).toBe(
      GRAPH_OUTCOME_BORDER_COLOR,
    );
  });
});
