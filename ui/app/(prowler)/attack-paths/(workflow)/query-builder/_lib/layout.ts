/**
 * Pure Dagre layout adapter for React Flow
 * Converts normalized GraphNode[] + GraphEdge[] to positioned RF nodes
 */

import { Graph, layout as dagreLayout } from "@dagrejs/dagre";
import { type Edge, type Node, Position } from "@xyflow/react";

import type { GraphEdge, GraphNode } from "@/types/attack-paths";

// Node dimensions matching the rendered React Flow custom nodes.
const RESOURCE_NODE_WIDTH = 136;
const RESOURCE_NODE_HEIGHT = 112;
const FINDING_NODE_WIDTH = 150;
const FINDING_NODE_HEIGHT = 112;
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

export const isFindingNode = (labels: string[]): boolean =>
  labels.some((l) => l.toLowerCase().includes("finding"));

const getNodeType = (labels: string[]): NodeType => {
  if (isFindingNode(labels)) return NODE_TYPE.FINDING;
  if (labels.some((l) => l.toLowerCase() === "internet"))
    return NODE_TYPE.INTERNET;
  return NODE_TYPE.RESOURCE;
};

const getNodeDimensions = (
  type: NodeType,
): { width: number; height: number } => {
  if (type === NODE_TYPE.FINDING)
    return { width: FINDING_NODE_WIDTH, height: FINDING_NODE_HEIGHT };
  if (type === NODE_TYPE.INTERNET)
    return { width: INTERNET_DIAMETER, height: INTERNET_DIAMETER };
  return { width: RESOURCE_NODE_WIDTH, height: RESOURCE_NODE_HEIGHT };
};

/**
 * Pure layout function: computes positioned React Flow nodes from graph data.
 * Deterministic — same inputs always produce same outputs.
 */
export const layoutWithDagre = (
  nodes: GraphNode[],
  edges: GraphEdge[],
): { rfNodes: Node<NodeData>[]; rfEdges: Edge[] } => {
  const g = new Graph({ multigraph: true });
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
      g.setEdge(
        sourceId,
        targetId,
        {
          id: edge.id,
          originalSource: edge.source,
          originalTarget: edge.target,
        },
        edge.id,
      );
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
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: { graphNode: node },
      width,
      height,
    };
  });

  // Build RF edges from dagre edges (using layout order, not original)
  const rfEdges: Edge[] = g
    .edges()
    .map((e: { v: string; w: string; name?: string }) => {
      const edgeData = g.edge(e) as {
        id?: string;
        originalSource: string;
        originalTarget: string;
      };

      // Check if either end is a finding node
      const sourceNode = nodes.find((n) => n.id === e.v);
      const targetNode = nodes.find((n) => n.id === e.w);
      const hasFinding =
        isFindingNode(sourceNode?.labels ?? []) ||
        isFindingNode(targetNode?.labels ?? []);

      return {
        id: edgeData.id ?? e.name ?? `${e.v}-${e.w}`,
        source: e.v,
        target: e.w,
        animated: hasFinding,
        className: hasFinding ? "finding-edge" : "resource-edge",
        data: {
          pathKey: `${e.v}-${e.w}`,
          originalSource: edgeData.originalSource,
          originalTarget: edgeData.originalTarget,
        },
      };
    });

  return { rfNodes, rfEdges };
};
