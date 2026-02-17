/**
 * Utility functions for attack path graph operations
 */

import type { AttackPathGraphData } from "@/types/attack-paths";

/**
 * Type for edge node reference - can be a string ID or an object with id property
 * Note: We use `object` to match GraphEdge type from attack-paths.ts
 */
export type EdgeNodeRef = string | object;

/**
 * Helper to get edge source/target ID from string or object
 */
export const getEdgeNodeId = (nodeRef: EdgeNodeRef): string => {
  if (typeof nodeRef === "string") {
    return nodeRef;
  }
  // Edge node references are objects with an id property
  return (nodeRef as { id: string }).id;
};

/**
 * Compute a filtered subgraph containing only the path through the target node.
 * This follows the directed graph structure of attack paths:
 * - Upstream: traces back to the root (AWS Account)
 * - Downstream: traces forward to leaf nodes
 * - Also includes findings connected to the selected node
 */
export const computeFilteredSubgraph = (
  fullData: AttackPathGraphData,
  targetNodeId: string,
): AttackPathGraphData => {
  const nodes = fullData.nodes;
  const edges = fullData.edges || [];

  // Build directed adjacency lists
  const forwardEdges = new Map<string, Set<string>>(); // source -> targets
  const backwardEdges = new Map<string, Set<string>>(); // target -> sources
  nodes.forEach((node) => {
    forwardEdges.set(node.id, new Set());
    backwardEdges.set(node.id, new Set());
  });

  edges.forEach((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    forwardEdges.get(sourceId)?.add(targetId);
    backwardEdges.get(targetId)?.add(sourceId);
  });

  const visibleNodeIds = new Set<string>();
  visibleNodeIds.add(targetNodeId);

  // Traverse upstream (backward) - find all ancestors
  const traverseUpstream = (nodeId: string) => {
    const sources = backwardEdges.get(nodeId);
    if (sources) {
      sources.forEach((sourceId) => {
        if (!visibleNodeIds.has(sourceId)) {
          visibleNodeIds.add(sourceId);
          traverseUpstream(sourceId);
        }
      });
    }
  };

  // Traverse downstream (forward) - find all descendants
  const traverseDownstream = (nodeId: string) => {
    const targets = forwardEdges.get(nodeId);
    if (targets) {
      targets.forEach((targetId) => {
        if (!visibleNodeIds.has(targetId)) {
          visibleNodeIds.add(targetId);
          traverseDownstream(targetId);
        }
      });
    }
  };

  // Start traversal from the target node
  traverseUpstream(targetNodeId);
  traverseDownstream(targetNodeId);

  // Also include findings directly connected to the selected node
  edges.forEach((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    const sourceNode = nodes.find((n) => n.id === sourceId);
    const targetNode = nodes.find((n) => n.id === targetId);

    const sourceIsFinding = sourceNode?.labels.some((l) =>
      l.toLowerCase().includes("finding"),
    );
    const targetIsFinding = targetNode?.labels.some((l) =>
      l.toLowerCase().includes("finding"),
    );

    // Include findings connected to the selected node
    if (sourceId === targetNodeId && targetIsFinding) {
      visibleNodeIds.add(targetId);
    }
    if (targetId === targetNodeId && sourceIsFinding) {
      visibleNodeIds.add(sourceId);
    }
  });

  // Filter nodes and edges to only include visible ones
  const filteredNodes = nodes.filter((node) => visibleNodeIds.has(node.id));
  const filteredEdges = edges.filter((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    return visibleNodeIds.has(sourceId) && visibleNodeIds.has(targetId);
  });

  return {
    nodes: filteredNodes,
    edges: filteredEdges,
  };
};

/**
 * Find edges in the path from a given node.
 * Upstream: follows only ONE parent path (first parent at each level) to avoid lighting up siblings
 * Downstream: follows ALL children recursively
 *
 * Uses pre-built adjacency maps for O(1) lookups instead of O(n) array searches per traversal step.
 *
 * @param nodeId - The starting node ID
 * @param edges - Array of edges with sourceId and targetId
 * @returns Set of edge IDs in the format "sourceId-targetId"
 */
export const getPathEdges = (
  nodeId: string,
  edges: Array<{ sourceId: string; targetId: string }>,
): Set<string> => {
  // Build adjacency maps once - O(n)
  const parentMap = new Map<string, { sourceId: string; targetId: string }>();
  const childrenMap = new Map<
    string,
    Array<{ sourceId: string; targetId: string }>
  >();

  edges.forEach((edge) => {
    // First parent only (matches original behavior of find())
    if (!parentMap.has(edge.targetId)) {
      parentMap.set(edge.targetId, edge);
    }
    const children = childrenMap.get(edge.sourceId) || [];
    children.push(edge);
    childrenMap.set(edge.sourceId, children);
  });

  const pathEdgeIds = new Set<string>();
  const visitedNodes = new Set<string>();

  // Traverse upstream - only follow ONE parent at each level (first found)
  // This creates a single path to the root, not all paths
  const traverseUpstream = (currentNodeId: string) => {
    if (visitedNodes.has(`up-${currentNodeId}`)) return;
    visitedNodes.add(`up-${currentNodeId}`);

    const parentEdge = parentMap.get(currentNodeId); // O(1) lookup
    if (parentEdge) {
      pathEdgeIds.add(`${parentEdge.sourceId}-${parentEdge.targetId}`);
      traverseUpstream(parentEdge.sourceId);
    }
  };

  // Traverse downstream (find ALL targets from this node)
  const traverseDownstream = (currentNodeId: string) => {
    if (visitedNodes.has(`down-${currentNodeId}`)) return;
    visitedNodes.add(`down-${currentNodeId}`);

    const children = childrenMap.get(currentNodeId) || []; // O(1) lookup
    children.forEach((edge) => {
      pathEdgeIds.add(`${edge.sourceId}-${edge.targetId}`);
      traverseDownstream(edge.targetId);
    });
  };

  traverseUpstream(nodeId);
  traverseDownstream(nodeId);

  return pathEdgeIds;
};
