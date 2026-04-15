/**
 * Pure Dagre layout adapter for React Flow
 * Converts normalized GraphNode[] + GraphEdge[] to positioned RF nodes
 *
 * Note: Uses dynamic import of @dagrejs/dagre to avoid type conflicts
 * with @types/dagre (which will be removed in PR3 when old dagre is removed).
 */

const dagreModule = require("@dagrejs/dagre");
const DagreGraph = dagreModule.Graph as new () => {
  setGraph: (opts: Record<string, unknown>) => void;
  setDefaultEdgeLabel: (fn: () => Record<string, unknown>) => void;
  setNode: (id: string, label: Record<string, unknown>) => void;
  setEdge: (
    source: string,
    target: string,
    label: Record<string, unknown>,
  ) => void;
  node: (id: string) => { x: number; y: number };
  edges: () => Array<{ v: string; w: string }>;
  edge: (e: { v: string; w: string }) => Record<string, unknown>;
};
const dagreLayout = dagreModule.layout as (g: unknown) => void;

import type { Edge, Node } from "@xyflow/react";

import type { GraphEdge, GraphNode } from "@/types/attack-paths";

// Node dimensions matching the original D3 implementation
const NODE_WIDTH = 180;
const NODE_HEIGHT = 50;
const HEXAGON_WIDTH = 200;
const HEXAGON_HEIGHT = 55;
const INTERNET_DIAMETER = 80; // NODE_HEIGHT * 0.8 * 2

// Container relationships that get reversed for proper hierarchy
const CONTAINER_RELATIONS = new Set([
  "RUNS_IN",
  "BELONGS_TO",
  "LOCATED_IN",
  "PART_OF",
]);

interface NodeData extends Record<string, unknown> {
  graphNode: GraphNode;
}

const NODE_TYPE = {
  FINDING: "finding",
  INTERNET: "internet",
  RESOURCE: "resource",
} as const;

type NodeType = (typeof NODE_TYPE)[keyof typeof NODE_TYPE];

const getNodeType = (labels: string[]): NodeType => {
  if (labels.some((l) => l.toLowerCase().includes("finding")))
    return NODE_TYPE.FINDING;
  if (labels.some((l) => l.toLowerCase() === "internet"))
    return NODE_TYPE.INTERNET;
  return NODE_TYPE.RESOURCE;
};

const getNodeDimensions = (
  type: NodeType,
): { width: number; height: number } => {
  if (type === NODE_TYPE.FINDING)
    return { width: HEXAGON_WIDTH, height: HEXAGON_HEIGHT };
  if (type === NODE_TYPE.INTERNET)
    return { width: INTERNET_DIAMETER, height: INTERNET_DIAMETER };
  return { width: NODE_WIDTH, height: NODE_HEIGHT };
};

/**
 * Pure layout function: computes positioned React Flow nodes from graph data.
 * Deterministic — same inputs always produce same outputs.
 */
export const layoutWithDagre = (
  nodes: GraphNode[],
  edges: GraphEdge[],
): { rfNodes: Node<NodeData>[]; rfEdges: Edge[] } => {
  const g = new DagreGraph();
  g.setGraph({
    rankdir: "LR",
    nodesep: 80,
    ranksep: 150,
    marginx: 50,
    marginy: 50,
  });
  g.setDefaultEdgeLabel(() => ({}));

  // Add nodes with type-based dimensions
  nodes.forEach((node) => {
    const type = getNodeType(node.labels);
    const { width, height } = getNodeDimensions(type);
    g.setNode(node.id, { label: node.id, width, height });
  });

  // Add edges, reversing container relationships for proper hierarchy
  edges.forEach((edge) => {
    let sourceId = edge.source;
    let targetId = edge.target;

    if (CONTAINER_RELATIONS.has(edge.type)) {
      [sourceId, targetId] = [targetId, sourceId];
    }

    if (sourceId && targetId) {
      g.setEdge(sourceId, targetId, {
        originalSource: edge.source,
        originalTarget: edge.target,
      });
    }
  });

  dagreLayout(g);

  // Build RF nodes from layout
  const rfNodes: Node<NodeData>[] = nodes.map((node) => {
    const dagreNode = g.node(node.id);
    const type = getNodeType(node.labels);
    const { width, height } = getNodeDimensions(type);

    return {
      id: node.id,
      type,
      position: {
        x: dagreNode.x - width / 2,
        y: dagreNode.y - height / 2,
      },
      data: { graphNode: node },
      width,
      height,
    };
  });

  // Build RF edges from dagre edges (using layout order, not original)
  const rfEdges: Edge[] = g.edges().map((e: { v: string; w: string }) => {
    const edgeData = g.edge(e) as {
      originalSource: string;
      originalTarget: string;
    };

    // Check if either end is a finding node
    const sourceNode = nodes.find((n) => n.id === e.v);
    const targetNode = nodes.find((n) => n.id === e.w);
    const hasFinding =
      sourceNode?.labels.some((l) => l.toLowerCase().includes("finding")) ||
      targetNode?.labels.some((l) => l.toLowerCase().includes("finding"));

    return {
      id: `${e.v}-${e.w}`,
      source: e.v,
      target: e.w,
      animated: hasFinding,
      className: hasFinding ? "finding-edge" : "resource-edge",
      data: {
        originalSource: edgeData.originalSource,
        originalTarget: edgeData.originalTarget,
      },
    };
  });

  return { rfNodes, rfEdges };
};
