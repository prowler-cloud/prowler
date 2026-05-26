import { describe, expect, it } from "vitest";

import type { AttackPathGraphData, GraphNode } from "@/types/attack-paths";

import {
  ATTACK_PATH_GROUP_LABEL,
  ATTACK_PATH_OUTCOME_LABEL,
  buildTemplateGraph,
  isGroupNode,
  isOutcomeNode,
  OUTCOME_NODE_ID,
} from "./template-graph";

const role = (id: string): GraphNode => ({
  id,
  labels: ["AWSRole"],
  properties: { name: id },
});

const instance = (id: string): GraphNode => ({
  id,
  labels: ["EC2Instance"],
  properties: { name: id },
});

const outcome = {
  label: "Code execution",
  description: "Run code with the role's privileges.",
  severity: "high",
};

// Two roles and two instances; each role can act on each instance.
const baseData: AttackPathGraphData = {
  nodes: [role("role-1"), role("role-2"), instance("ec2-1"), instance("ec2-2")],
  edges: [
    { id: "e1", source: "role-1", target: "ec2-1", type: "CAN_X" },
    { id: "e2", source: "role-2", target: "ec2-2", type: "CAN_X" },
  ],
};

describe("buildTemplateGraph", () => {
  it("collapses concrete nodes into one group node per type", () => {
    const { nodes } = buildTemplateGraph(baseData, new Set(), null);

    const groups = nodes.filter(isGroupNode);
    expect(groups).toHaveLength(2);

    const byType = new Map(
      groups.map((g) => [String(g.properties.typeKey), g.properties.count]),
    );
    expect(byType.get("AWS Role")).toBe(2);
    expect(byType.get("EC2 Instance")).toBe(2);
  });

  it("dedupes and collapses edges between groups, dropping self-loops", () => {
    const { edges = [] } = buildTemplateGraph(baseData, new Set(), null);

    // Both concrete edges collapse to a single AWS Role group -> EC2 group edge
    const stepEdges = edges.filter((e) => e.target.startsWith("group:"));
    expect(stepEdges).toHaveLength(1);
    expect(stepEdges[0].source).toBe("group:AWS Role");
    expect(stepEdges[0].target).toBe("group:EC2 Instance");
  });

  it("expands a single type into its concrete members", () => {
    const { nodes } = buildTemplateGraph(
      baseData,
      new Set(["AWS Role"]),
      null,
    );

    // Roles are now concrete; instances remain a group.
    expect(nodes.some((n) => n.id === "role-1")).toBe(true);
    expect(nodes.some((n) => n.id === "role-2")).toBe(true);
    expect(nodes.some((n) => n.id === "group:AWS Role")).toBe(false);
    expect(nodes.some((n) => n.id === "group:EC2 Instance")).toBe(true);
  });

  it("appends an outcome node connected from sink representatives", () => {
    const { nodes, edges = [] } = buildTemplateGraph(
      baseData,
      new Set(),
      outcome,
    );

    const outcomeNodes = nodes.filter(isOutcomeNode);
    expect(outcomeNodes).toHaveLength(1);
    expect(outcomeNodes[0].id).toBe(OUTCOME_NODE_ID);
    expect(outcomeNodes[0].labels).toContain(ATTACK_PATH_OUTCOME_LABEL);

    // The EC2 group is the sink → it connects to the outcome.
    const toOutcome = edges.filter((e) => e.target === OUTCOME_NODE_ID);
    expect(toOutcome).toHaveLength(1);
    expect(toOutcome[0].source).toBe("group:EC2 Instance");
  });

  it("omits the outcome node when no outcome is provided", () => {
    const { nodes } = buildTemplateGraph(baseData, new Set(), null);
    expect(nodes.some(isOutcomeNode)).toBe(false);
  });

  it("drops finding and account nodes from the structural view", () => {
    const data: AttackPathGraphData = {
      nodes: [
        role("role-1"),
        { id: "acc", labels: ["AWSAccount"], properties: {} },
        {
          id: "f1",
          labels: ["ProwlerFinding"],
          properties: { severity: "high" },
        },
      ],
      edges: [
        { id: "e1", source: "acc", target: "role-1", type: "RESOURCE" },
        { id: "e2", source: "role-1", target: "f1", type: "HAS_FINDING" },
      ],
    };

    const { nodes, edges = [] } = buildTemplateGraph(data, new Set(), null);

    expect(nodes.some((n) => n.labels.includes("AWSAccount"))).toBe(false);
    expect(nodes.some((n) => n.labels.includes("ProwlerFinding"))).toBe(false);
    // Only the AWS Role group survives; its account/finding edges are gone.
    expect(nodes).toHaveLength(1);
    expect(nodes[0].labels).toContain(ATTACK_PATH_GROUP_LABEL);
    expect(edges).toHaveLength(0);
  });

  it("returns an empty graph for empty input", () => {
    const { nodes, edges } = buildTemplateGraph(null, new Set(), outcome);
    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });
});
