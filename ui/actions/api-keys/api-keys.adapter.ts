import {
  ApiKeyResponse,
  EnrichedApiKey,
} from "@/components/users/profile/api-keys/types";
import { getApiKeyUserEmail } from "@/components/users/profile/api-keys/utils";
import { MetaDataProps } from "@/types";

/**
 * Adapts the raw API response to enriched API keys with metadata
 * - Resolves user email from included resources
 * - Co-locates data for better performance
 * - Preserves pagination metadata
 *
 * @param response - Raw API response with data and included resources
 * @returns Object with enriched API keys and metadata
 */
export function adaptApiKeysResponse(response: ApiKeyResponse | undefined): {
  data: EnrichedApiKey[];
  metadata?: MetaDataProps;
} {
  if (!response?.data) {
    return { data: [] };
  }

  const enrichedData = response.data.map((key) => ({
    ...key,
    userEmail: getApiKeyUserEmail(key, response.included),
  }));

  // Transform meta to MetaDataProps format if pagination exists
  const metadata: MetaDataProps | undefined = response.meta?.pagination
    ? {
        pagination: {
          page: response.meta.pagination.page,
          pages: response.meta.pagination.pages,
          count: response.meta.pagination.count,
          itemsPerPage: [10, 25, 50, 100],
        },
        version: "1.0",
      }
    : undefined;

  return { data: enrichedData, metadata };
}
