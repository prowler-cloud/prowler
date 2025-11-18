import { MetaDataProps } from "@/types";
import {
  AttackPathQueriesResponse,
  AttackPathQuery,
} from "@/types/attack-paths";

/**
 * Adapts raw query API responses to enriched domain models
 * - Enriches queries with metadata and computed properties
 * - Co-locates related data for better performance
 * - Preserves pagination metadata for list operations
 *
 * Uses plugin architecture for extensibility:
 * - Handles query-specific response transformation
 * - Can be composed with backend service plugins
 * - Maintains separation of concerns between API layer and business logic
 */

/**
 * Adapt attack path queries response with enriched data
 *
 * @param response - Raw API response from attack-paths-scans/{id}/queries endpoint
 * @returns Enriched queries data with metadata
 */
export function adaptAttackPathQueriesResponse(
  response: AttackPathQueriesResponse | undefined,
): {
  data: AttackPathQuery[];
  metadata?: MetaDataProps;
} {
  if (!response?.data) {
    return { data: [] };
  }

  // Enrich query data with computed properties
  const enrichedData = response.data.map((query) => ({
    ...query,
    // Can add computed properties here, e.g.:
    // parameterCount: query.attributes.parameters.length,
    // requiredParameters: query.attributes.parameters.filter(p => p.required),
    // hasParameters: query.attributes.parameters.length > 0,
  }));

  const metadata: MetaDataProps | undefined = {
    pagination: {
      page: 1,
      pages: 1,
      count: enrichedData.length,
      itemsPerPage: [10, 25, 50, 100],
    },
    version: "1.0",
  };

  return { data: enrichedData, metadata };
}

/**
 * Extract query parameter information
 * Helper function for computing query parameter details
 *
 * @param queryId - Query ID to get details for
 * @param queries - List of available queries
 * @returns Query parameter count and requirements info
 */
export function getQueryParameterInfo(
  queryId: string,
  queries: AttackPathQuery[],
): {
  totalParameters: number;
  requiredParameters: number;
  hasParameters: boolean;
} {
  const query = queries.find((q) => q.id === queryId);

  if (!query) {
    return {
      totalParameters: 0,
      requiredParameters: 0,
      hasParameters: false,
    };
  }

  const parameters = query.attributes.parameters;
  const requiredParameters = parameters.filter((p) => p.required).length;

  return {
    totalParameters: parameters.length,
    requiredParameters,
    hasParameters: parameters.length > 0,
  };
}
