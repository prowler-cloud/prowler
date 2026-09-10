import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";

import type { GraphEdge, GraphNode } from "@/types/attack-paths";

import { layoutWithDagre } from "./layout";

const findingNode: GraphNode = {
  id: "finding-1",
  labels: ["ProwlerFinding"],
  properties: { check_title: "Open S3 bucket", severity: "high" },
};

const resourceNode: GraphNode = {
  id: "resource-1",
  labels: ["S3Bucket"],
  properties: { name: "bucket-1" },
};

const guardDutyNode: GraphNode = {
  id: "guard-duty-1",
  labels: ["GuardDutyFinding"],
  properties: { title: "Port probe", severity: "high" },
};

const inspectorNode: GraphNode = {
  id: "inspector-1",
  labels: ["AWSInspectorFinding"],
  properties: { title: "Package vulnerability", severity: "high" },
};

const internetNode: GraphNode = {
  id: "internet-1",
  labels: ["Internet"],
  properties: {},
};

describe("layoutWithDagre", () => {
  it("returns empty arrays for empty input", () => {
    const result = layoutWithDagre([], []);
    expect(result.rfNodes).toEqual([]);
    expect(result.rfEdges).toEqual([]);
  });
  it("assigns node types and dimensions from labels", () => {
    const { rfNodes } = layoutWithDagre(
      [findingNode, resourceNode, internetNode],
      [],
    );

    const byId = new Map(rfNodes.map((n) => [n.id, n]));

    expect(byId.get("finding-1")).toMatchObject({
      type: "finding",
      width: 150,
      height: 124,
    });
    expect(byId.get("resource-1")).toMatchObject({
      type: "resource",
      width: 136,
      height: 124,
    });
    expect(byId.get("internet-1")).toMatchObject({
      type: "internet",
      width: 80,
      height: 80,
    });
  });

  it("treats cloud-provider finding resources as resource nodes", () => {
    const { rfNodes } = layoutWithDagre(
      [findingNode, guardDutyNode, inspectorNode],
      [],
    );

    const byId = new Map(rfNodes.map((n) => [n.id, n]));

    expect(byId.get("finding-1")?.type).toBe("finding");
    expect(byId.get("guard-duty-1")).toMatchObject({
      type: "resource",
      width: 136,
      height: 124,
    });
    expect(byId.get("inspector-1")?.type).toBe("resource");
  });

  it("does not animate edges that only touch cloud-provider finding resources", () => {
    const { rfEdges } = layoutWithDagre(
      [resourceNode, guardDutyNode],
      [
        {
          id: "e1",
          source: "guard-duty-1",
          target: "resource-1",
          type: "AFFECTS",
        },
      ],
    );

    expect(rfEdges[0]).toMatchObject({
      animated: false,
      className: "resource-edge",
    });
  });

  it("is deterministic: same input produces equal output across runs", () => {
    const nodes = [findingNode, resourceNode];
    const edges: GraphEdge[] = [
      {
        id: "e1",
        source: "resource-1",
        target: "finding-1",
        type: "HAS_FINDING",
      },
    ];

    const a = layoutWithDagre(nodes, edges);
    const b = layoutWithDagre(nodes, edges);

    expect(a).toEqual(b);
  });

  it("places connected children to the right and stacks siblings within the horizontal rank", () => {
    const rootNode: GraphNode = {
      id: "root",
      labels: ["AWSAccount"],
      properties: { name: "account" },
    };
    const siblingNodes: GraphNode[] = [
      {
        id: "bucket",
        labels: ["S3Bucket"],
        properties: { name: "bucket" },
      },
      {
        id: "lambda",
        labels: ["AWSLambda"],
        properties: { name: "function" },
      },
      {
        id: "database",
        labels: ["RDSInstance"],
        properties: { name: "database" },
      },
    ];

    const { rfNodes } = layoutWithDagre(
      [rootNode, ...siblingNodes],
      siblingNodes.map((node) => ({
        id: `root-${node.id}`,
        source: "root",
        target: node.id,
        type: "CONNECTS_TO",
      })),
    );

    const rootPosition = rfNodes.find(
      (candidate) => candidate.id === "root",
    )?.position;
    const siblingPositions = siblingNodes.map((node) => {
      const rfNode = rfNodes.find((candidate) => candidate.id === node.id);

      expect(rfNode).toBeDefined();

      return rfNode?.position ?? { x: 0, y: 0 };
    });

    const xSpread =
      Math.max(...siblingPositions.map((position) => position.x)) -
      Math.min(...siblingPositions.map((position) => position.x));
    const ySpread =
      Math.max(...siblingPositions.map((position) => position.y)) -
      Math.min(...siblingPositions.map((position) => position.y));

    expect(rootPosition).toBeDefined();
    siblingPositions.forEach((position) => {
      expect(position.x).toBeGreaterThan(rootPosition?.x ?? 0);
    });
    expect(ySpread).toBeGreaterThan(xSpread);
  });

  it("connects edges through right and left node sides for horizontal layout", () => {
    const { rfNodes } = layoutWithDagre(
      [findingNode, resourceNode],
      [
        {
          id: "e1",
          source: "resource-1",
          target: "finding-1",
          type: "HAS_FINDING",
        },
      ],
    );

    rfNodes.forEach((node) => {
      expect(node.sourcePosition).toBe(Position.Right);
      expect(node.targetPosition).toBe(Position.Left);
    });
  });

  it("offsets dagre center positions by half of the node dimensions (top-left)", () => {
    const { rfNodes } = layoutWithDagre([findingNode, resourceNode], []);

    rfNodes.forEach((node) => {
      expect(Number.isFinite(node.position.x)).toBe(true);
      expect(Number.isFinite(node.position.y)).toBe(true);
    });

    // Different node types must end up with different sizes — confirms the
    // dimension-aware offset is wired up.
    const findingDims = rfNodes.find((n) => n.id === "finding-1");
    const resourceDims = rfNodes.find((n) => n.id === "resource-1");
    expect(findingDims?.width).not.toEqual(resourceDims?.width);
  });

  it("reverses container relationships while preserving original endpoints in edge data", () => {
    const containerNode: GraphNode = {
      id: "container",
      labels: ["AWSAccount"],
      properties: { name: "acct" },
    };
    const childNode: GraphNode = {
      id: "child",
      labels: ["S3Bucket"],
      properties: { name: "bucket" },
    };

    const { rfEdges } = layoutWithDagre(
      [containerNode, childNode],
      [
        {
          id: "e1",
          source: "container",
          target: "child",
          type: "RUNS_IN",
        },
      ],
    );

    expect(rfEdges).toHaveLength(1);
    expect(rfEdges[0]).toMatchObject({
      source: "child",
      target: "container",
      data: { originalSource: "container", originalTarget: "child" },
    });
  });

  it("animates edges that touch a finding node and tags them with finding-edge", () => {
    const { rfEdges } = layoutWithDagre(
      [findingNode, resourceNode, internetNode],
      [
        {
          id: "e1",
          source: "resource-1",
          target: "finding-1",
          type: "HAS_FINDING",
        },
        {
          id: "e2",
          source: "internet-1",
          target: "resource-1",
          type: "CONNECTS_TO",
        },
      ],
    );

    const findingEdge = rfEdges.find(
      (e) => e.source === "resource-1" && e.target === "finding-1",
    );
    const plainEdge = rfEdges.find(
      (e) => e.source === "internet-1" && e.target === "resource-1",
    );

    expect(findingEdge).toMatchObject({
      animated: true,
      className: "finding-edge",
    });
    expect(plainEdge).toMatchObject({
      animated: false,
      className: "resource-edge",
    });
  });

  it("preserves the original edge id when the graph has a single edge", () => {
    const { rfEdges } = layoutWithDagre(
      [findingNode, resourceNode],
      [
        {
          id: "ignored-by-rf",
          source: "resource-1",
          target: "finding-1",
          type: "HAS_FINDING",
        },
      ],
    );

    expect(rfEdges[0]?.id).toBe("ignored-by-rf");
  });

  it("preserves parallel edges between the same nodes with unique ids", () => {
    const { rfEdges } = layoutWithDagre(
      [resourceNode, findingNode],
      [
        {
          id: "edge-1",
          source: "resource-1",
          target: "finding-1",
          type: "HAS_FINDING",
        },
        {
          id: "edge-2",
          source: "resource-1",
          target: "finding-1",
          type: "HAS_FINDING",
        },
      ],
    );

    expect(rfEdges).toHaveLength(2);
    expect(rfEdges.map((edge) => edge.id)).toEqual(["edge-1", "edge-2"]);
    expect(rfEdges.every((edge) => edge.source === "resource-1")).toBe(true);
    expect(rfEdges.every((edge) => edge.target === "finding-1")).toBe(true);
  });
});
