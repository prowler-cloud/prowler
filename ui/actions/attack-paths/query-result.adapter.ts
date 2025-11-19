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
  value: GraphNodePropertyValue | GraphNodePropertyValue[] | Record<string, unknown>,
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
  properties: Record<string, GraphNodePropertyValue | GraphNodePropertyValue[] | Record<string, unknown>>,
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
 *
 * @param graphData - Raw graph data with nodes and relationships from API
 * @returns Graph data with edges array formatted for D3 visualization
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
  }));

  // Transform relationships into D3-compatible edges if relationships exist
  const edges: GraphEdge[] =
    (graphData.relationships as GraphRelationship[] | undefined)?.map(
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
    ) ?? [];

  return {
    nodes: normalizedNodes,
    edges,
    relationships: graphData.relationships, // Preserve original relationships data
  };
}
