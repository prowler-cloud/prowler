import { DOCS_URLS } from "@/lib/external-urls";
import { MetaDataProps } from "@/types";
import {
  ATTACK_PATH_QUERY_IDS,
  AttackPathQueriesResponse,
  AttackPathQuery,
  QUERY_PARAMETER_INPUT_TYPES,
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

const CUSTOM_QUERY_PLACEHOLDER = `MATCH (n)
RETURN n
LIMIT 25`;

const CUSTOM_QUERY_DOCUMENTATION_LINK = {
  text: "Learn how to write custom openCypher queries",
  link: DOCS_URLS.ATTACK_PATHS_CUSTOM_QUERIES,
} as const;

const createCustomQuery = (): AttackPathQuery => ({
  type: "attack-paths-scans",
  id: ATTACK_PATH_QUERY_IDS.CUSTOM,
  attributes: {
    name: "Custom openCypher query",
    short_description: "Write and run your own read-only query",
    description:
      "Run a read-only openCypher query against the selected Attack Paths scan. Results are automatically scoped to the selected provider.",
    provider: "custom",
    attribution: null,
    documentation_link: { ...CUSTOM_QUERY_DOCUMENTATION_LINK },
    parameters: [
      {
        name: "query",
        label: "openCypher",
        data_type: "string",
        description: "",
        placeholder: CUSTOM_QUERY_PLACEHOLDER,
        required: true,
        input_type: QUERY_PARAMETER_INPUT_TYPES.CODE_EDITOR,
        editor_language: "openCypher",
        requirement_badge: "Read-only*",
      },
    ],
  },
});

export const buildAttackPathQueries = (
  queries: AttackPathQuery[],
): AttackPathQuery[] => {
  return [createCustomQuery(), ...queries];
};
