/**
 * Utility functions for attack path graph operations
 */

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
