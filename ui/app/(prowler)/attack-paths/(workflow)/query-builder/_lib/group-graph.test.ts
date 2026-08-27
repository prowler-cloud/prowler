import { describe, expect, it } from "vitest";

import type {
  AttackPathGraphData,
  AttackPathOutcome,
  GraphNode,
} from "@/types/attack-paths";

import {
  buildAttackPathView,
  GROUP_NODE_LABEL,
  GROUP_PROPS,
  groupKey,
  OUTCOME_NODE_LABEL,
  OUTCOME_PROPS,
} from "./group-graph";

const node = (id: string, label: string): GraphNode => ({
  id,
  labels: [label],
  properties: { name: id },
});

// hub -> role (singleton) -> 3 policies (collapsed group).
// finding-r hangs off the visible role; finding-p hangs off a collapsed policy.
const baseGraph: AttackPathGraphData = {
  nodes: [
    node("acct", "AWSAccount"),
    node("role-1", "AWSRole"),
    node("pol-1", "AWSPolicy"),
    node("pol-2", "AWSPolicy"),
    node("pol-3", "AWSPolicy"),
    node("finding-r", "ProwlerFinding"),
    node("finding-p", "ProwlerFinding"),
  ],
  edges: [
    { id: "e1", source: "acct", target: "role-1", type: "RESOURCE" },
    { id: "e2", source: "role-1", target: "pol-1", type: "POLICY" },
    { id: "e3", source: "role-1", target: "pol-2", type: "POLICY" },
    { id: "e4", source: "role-1", target: "pol-3", type: "POLICY" },
    { id: "e5", source: "role-1", target: "finding-r", type: "HAS_FINDING" },
    { id: "e6", source: "pol-1", target: "finding-p", type: "HAS_FINDING" },
  ],
};

const outcome: AttackPathOutcome = {
  kind: "code_execution",
  label: "Code execution",
  partial: false,
};

const idsOf = (nodes: GraphNode[]) => nodes.map((n) => n.id);

describe("buildAttackPathView", () => {
  it("drops the account hub", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    expect(view.nodes.some((n) => n.labels.includes("AWSAccount"))).toBe(false);
  });

  it("keeps findings of visible members but hides findings of collapsed ones", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    // role-1 is a visible singleton -> its finding stays
    expect(idsOf(view.nodes)).toContain("finding-r");
    // pol-1 is inside a collapsed group -> its finding is hidden
    expect(idsOf(view.nodes)).not.toContain("finding-p");
  });

  it("renders a singleton class as a plain node, not a group", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    const role = view.nodes.find((n) => n.id === "role-1");
    expect(role).toBeDefined();
    expect(role?.labels).not.toContain(GROUP_NODE_LABEL);
  });

  it("collapses a class with >=2 members into one group node with a count", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    const group = view.nodes.find((n) => n.labels.includes(GROUP_NODE_LABEL));
    expect(group).toBeDefined();
    expect(group?.properties[GROUP_PROPS.COUNT]).toBe(3);
    expect(idsOf(view.nodes)).not.toContain("pol-1");
  });

  it("flags a collapsed group whose members carry findings", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    const group = view.nodes.find((n) => n.labels.includes(GROUP_NODE_LABEL));
    expect(group?.properties[GROUP_PROPS.HAS_FINDINGS]).toBe(true);
  });

  it("aggregates parallel edges into one group edge with a count", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    const groupId = view.nodes.find((n) =>
      n.labels.includes(GROUP_NODE_LABEL),
    )?.id;
    const roleToGroup = view.edges.filter(
      (e) => e.source === "role-1" && e.target === groupId,
    );
    expect(roleToGroup).toHaveLength(1);
    expect(roleToGroup[0].properties?.__count).toBe(3);
  });

  it("expands a group to its members and reveals their findings", () => {
    const key = groupKey(1, "AWSPolicy");
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set([key]),
    });
    expect(idsOf(view.nodes)).toEqual(
      expect.arrayContaining(["pol-1", "pol-2", "pol-3"]),
    );
    expect(view.nodes.some((n) => n.labels.includes(GROUP_NODE_LABEL))).toBe(
      false,
    );
    // pol-1 is now visible, so its finding passes through
    expect(idsOf(view.nodes)).toContain("finding-p");
  });

  it("injects a terminal outcome node attached to the sinks", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
      outcome,
    });
    const outcomeNode = view.nodes.find((n) =>
      n.labels.includes(OUTCOME_NODE_LABEL),
    );
    expect(outcomeNode).toBeDefined();
    expect(outcomeNode?.properties[OUTCOME_PROPS.LABEL]).toBe("Code execution");
    const intoOutcome = view.edges.filter(
      (e) => e.target === outcomeNode?.id && e.type === "OUTCOME",
    );
    expect(intoOutcome.length).toBeGreaterThan(0);
  });

  it("does not treat a node with only findings as a non-sink", () => {
    // role-1 has an outgoing HAS_FINDING edge but no resource edge to the group
    // when collapsed... it does have edges to the policy group, so the group is
    // the sink. Verify the outcome attaches to the policy group, not the finding.
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
      outcome,
    });
    const groupId = view.nodes.find((n) =>
      n.labels.includes(GROUP_NODE_LABEL),
    )?.id;
    const outcomeNode = view.nodes.find((n) =>
      n.labels.includes(OUTCOME_NODE_LABEL),
    );
    expect(
      view.edges.some(
        (e) => e.source === groupId && e.target === outcomeNode?.id,
      ),
    ).toBe(true);
  });

  it("injects no outcome node when outcome is absent", () => {
    const view = buildAttackPathView({
      data: baseGraph,
      expandedClasses: new Set(),
    });
    expect(view.nodes.some((n) => n.labels.includes(OUTCOME_NODE_LABEL))).toBe(
      false,
    );
  });

  it("attaches the outcome to all nodes when there is no clear sink", () => {
    const view = buildAttackPathView({
      data: { nodes: [node("principal-1", "AWSPrincipal")], edges: [] },
      expandedClasses: new Set(),
      outcome,
    });
    const outcomeNode = view.nodes.find((n) =>
      n.labels.includes(OUTCOME_NODE_LABEL),
    );
    expect(outcomeNode).toBeDefined();
    expect(
      view.edges.some(
        (e) => e.source === "principal-1" && e.target === outcomeNode?.id,
      ),
    ).toBe(true);
  });

  it("renders every member of an expanded class without dropping any", () => {
    const many: AttackPathGraphData = {
      nodes: [
        node("src", "AWSRole"),
        ...Array.from({ length: 40 }, (_, i) => node(`m-${i}`, "AWSPolicy")),
      ],
      edges: Array.from({ length: 40 }, (_, i) => ({
        id: `e-${i}`,
        source: "src",
        target: `m-${i}`,
        type: "POLICY",
      })),
    };
    const view = buildAttackPathView({
      data: many,
      expandedClasses: new Set([groupKey(1, "AWSPolicy")]),
    });
    const rendered = view.nodes.filter((n) => n.id.startsWith("m-")).length;
    // Expanding shows the complete set, so the path is never presented as
    // complete while silently omitting members.
    expect(rendered).toBe(40);

    // Every edge endpoint must resolve to a rendered node.
    const nodeIds = new Set(view.nodes.map((n) => n.id));
    for (const edge of view.edges) {
      expect(nodeIds.has(edge.source)).toBe(true);
      expect(nodeIds.has(edge.target)).toBe(true);
    }
  });

  it("keeps the outcome terminal across reversed container relationships", () => {
    // `instance-1 RUNS_IN vpc-1` is reversed by the layout, which renders
    // `vpc-1 -> instance-1` (container -> child). That makes instance-1 the
    // laid-out sink. Using the raw edge direction would instead treat vpc-1 as
    // the sink and hang the outcome off it as a mid-path sibling; the transform
    // must orient the edge the same way the layout does.
    const containerGraph: AttackPathGraphData = {
      nodes: [node("instance-1", "EC2Instance"), node("vpc-1", "VPC")],
      edges: [
        { id: "c1", source: "instance-1", target: "vpc-1", type: "RUNS_IN" },
      ],
    };
    const view = buildAttackPathView({
      data: containerGraph,
      expandedClasses: new Set(),
      outcome,
    });
    const outcomeNode = view.nodes.find((n) =>
      n.labels.includes(OUTCOME_NODE_LABEL),
    );
    expect(outcomeNode).toBeDefined();
    const intoOutcome = view.edges.filter(
      (e) => e.target === outcomeNode?.id && e.type === "OUTCOME",
    );
    // The outcome attaches to the laid-out sink (the child), not the container.
    expect(intoOutcome.map((e) => e.source)).toEqual(["instance-1"]);
  });

  it("returns an empty view when nothing survives hub removal", () => {
    const view = buildAttackPathView({
      data: {
        nodes: [node("acct", "AWSAccount")],
        edges: [],
      },
      expandedClasses: new Set(),
      outcome,
    });
    expect(view.nodes).toHaveLength(0);
    expect(view.edges).toHaveLength(0);
  });
});
