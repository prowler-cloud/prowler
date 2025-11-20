import {
  AttackPathGraphData,
  GraphEdge,
  GraphNodeProperties,
  GraphNodePropertyValue,
  GraphRelationship,
} from "@/types/attack-paths";

/**
 * Normalizes property values to ensure they are primitives
 * Arrays are converted to comma-separated strings
 *
 * @param value - The property value to normalize
 * @returns Normalized primitive value
 */
function normalizePropertyValue(
  value:
    | GraphNodePropertyValue
    | GraphNodePropertyValue[]
    | Record<string, unknown>,
): string | number | boolean | null | undefined {
  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    // Convert arrays to comma-separated strings
    return value.join(", ");
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  // For any other type, convert to string
  return String(value);
}

/**
 * Normalizes all properties in an object to ensure they are primitives
 *
 * @param properties - The properties object to normalize
 * @returns Normalized properties object
 */
function normalizeProperties(
  properties: Record<
    string,
    GraphNodePropertyValue | GraphNodePropertyValue[] | Record<string, unknown>
  >,
): GraphNodeProperties {
  const normalized: GraphNodeProperties = {};

  for (const [key, value] of Object.entries(properties)) {
    normalized[key] = normalizePropertyValue(value);
  }

  return normalized;
}

/**
 * Adapts graph query result data for D3 visualization
 * Transforms relationships array into edges array for D3 force-directed graph
 *
 * The adapter handles:
 * - Converting relationship objects to edge objects compatible with D3
 * - Mapping relationship labels to edge types for graph styling
 * - Normalizing array properties to strings (e.g., anonymous_actions: ["s3:GetObject"] -> "s3:GetObject")
 * - Preserving node and relationship data structure
 * - Adding findings array to each node based on HAS_FINDING edges
 * - Adding resources array to finding nodes based on HAS_FINDING edges (reverse relationship)
 *
 * @param graphData - Raw graph data with nodes and relationships from API
 * @returns Graph data with edges array formatted for D3 visualization and findings/resources on nodes
 */
export function adaptQueryResultToGraphData(
  graphData: AttackPathGraphData,
): AttackPathGraphData {
  // Normalize node properties to ensure all values are primitives
  const normalizedNodes = graphData.nodes.map((node) => ({
    ...node,
    properties: normalizeProperties(
      node.properties as Record<
        string,
        GraphNodePropertyValue | GraphNodePropertyValue[]
      >,
    ),
    findings: [] as string[], // Will be populated below
    resources: [] as string[], // Will be populated below for finding nodes
  }));

  // Transform relationships into D3-compatible edges if relationships exist
  // Also handle case where edges are already provided (e.g., from mock data)
  let edges: GraphEdge[] = [];

  if (graphData.relationships) {
    edges = (graphData.relationships as GraphRelationship[]).map(
      (relationship) => ({
        id: relationship.id,
        source: relationship.source,
        target: relationship.target,
        type: relationship.label, // D3 uses 'type' for styling edge appearance
        properties: relationship.properties
          ? normalizeProperties(
              relationship.properties as Record<
                string,
                GraphNodePropertyValue | GraphNodePropertyValue[]
              >,
            )
          : undefined,
      }),
    );
  } else if (graphData.edges) {
    // If edges are already provided, just normalize their properties
    edges = (graphData.edges as GraphEdge[]).map((edge) => ({
      ...edge,
      properties: edge.properties
        ? normalizeProperties(
            edge.properties as Record<
              string,
              GraphNodePropertyValue | GraphNodePropertyValue[]
            >,
          )
        : undefined,
    }));
  }

  // Populate findings and resources based on HAS_FINDING edges
  edges.forEach((edge) => {
    if (edge.type === "HAS_FINDING") {
      const sourceId =
        typeof edge.source === "string"
          ? edge.source
          : (edge.source as { id?: string })?.id;
      const targetId =
        typeof edge.target === "string"
          ? edge.target
          : (edge.target as { id?: string })?.id;

      if (sourceId && targetId) {
        // Add finding to source node (resource -> finding)
        const sourceNode = normalizedNodes.find((n) => n.id === sourceId);
        if (sourceNode) {
          sourceNode.findings.push(targetId);
        }

        // Add resource to target node (finding <- resource)
        const targetNode = normalizedNodes.find((n) => n.id === targetId);
        if (targetNode) {
          targetNode.resources.push(sourceId);
        }
      }
    }
  });

  return {
    nodes: normalizedNodes,
    edges,
    relationships: graphData.relationships, // Preserve original relationships data
  };
}
