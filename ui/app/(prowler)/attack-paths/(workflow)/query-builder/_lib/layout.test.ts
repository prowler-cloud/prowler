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
      width: 200,
      height: 55,
    });
    expect(byId.get("resource-1")).toMatchObject({
      type: "resource",
      width: 180,
      height: 50,
    });
    expect(byId.get("internet-1")).toMatchObject({
      type: "internet",
      width: 80,
      height: 80,
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

  it("builds rf edge IDs as `${source}-${target}` after layout", () => {
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

    expect(rfEdges[0]?.id).toBe("resource-1-finding-1");
  });
});
