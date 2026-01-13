/**
 * Utility functions for attack path graph operations
 */

/**
 * Find edges in the path from a given node.
 * Upstream: follows only ONE parent path (first parent at each level) to avoid lighting up siblings
 * Downstream: follows ALL children recursively
 *
 * @param nodeId - The starting node ID
 * @param edges - Array of edges with sourceId and targetId
 * @returns Set of edge IDs in the format "sourceId-targetId"
 */
export const getPathEdges = (
  nodeId: string,
  edges: Array<{ sourceId: string; targetId: string }>,
): Set<string> => {
  const pathEdgeIds = new Set<string>();
  const visitedNodes = new Set<string>();

  // Traverse upstream - only follow ONE parent at each level (first found)
  // This creates a single path to the root, not all paths
  const traverseUpstream = (currentNodeId: string) => {
    if (visitedNodes.has(`up-${currentNodeId}`)) return;
    visitedNodes.add(`up-${currentNodeId}`);

    // Find the first parent edge only
    const parentEdge = edges.find((edge) => edge.targetId === currentNodeId);
    if (parentEdge) {
      pathEdgeIds.add(`${parentEdge.sourceId}-${parentEdge.targetId}`);
      traverseUpstream(parentEdge.sourceId);
    }
  };

  // Traverse downstream (find ALL targets from this node)
  const traverseDownstream = (currentNodeId: string) => {
    if (visitedNodes.has(`down-${currentNodeId}`)) return;
    visitedNodes.add(`down-${currentNodeId}`);

    edges.forEach((edge) => {
      if (edge.sourceId === currentNodeId) {
        pathEdgeIds.add(`${edge.sourceId}-${edge.targetId}`);
        traverseDownstream(edge.targetId);
      }
    });
  };

  traverseUpstream(nodeId);
  traverseDownstream(nodeId);

  return pathEdgeIds;
};
