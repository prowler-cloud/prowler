import { AttackPathGraphData, GraphEdge } from "@/types/attack-paths";

/**
 * Adapts graph query result data for D3 visualization
 * Transforms relationships array into edges array for D3 force-directed graph
 *
 * The adapter handles:
 * - Converting relationship objects to edge objects compatible with D3
 * - Mapping relationship labels to edge types for graph styling
 * - Preserving node and relationship data structure
 *
 * @param graphData - Raw graph data with nodes and relationships from API
 * @returns Graph data with edges array formatted for D3 visualization
 */
export function adaptQueryResultToGraphData(
  graphData: AttackPathGraphData,
): AttackPathGraphData {
  // Transform relationships into D3-compatible edges if relationships exist
  const edges: GraphEdge[] = (graphData.relationships || []).map(
    (relationship) => ({
      id: relationship.id,
      source: relationship.source,
      target: relationship.target,
      type: relationship.label, // D3 uses 'type' for styling edge appearance
      properties: relationship.properties,
    }),
  );

  return {
    nodes: graphData.nodes,
    edges,
    relationships: graphData.relationships, // Preserve original relationships data
  };
}
