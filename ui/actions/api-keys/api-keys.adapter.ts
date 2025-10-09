import {
  ApiKeyData,
  ApiKeyResponse,
} from "@/components/users/profile/api-keys/types";
import { getApiKeyUserEmail } from "@/components/users/profile/api-keys/utils";

/**
 * Enriched API Key with included data already resolved
 * This eliminates the need for runtime lookups in components
 */
export interface EnrichedApiKey extends ApiKeyData {
  userEmail: string;
}

/**
 * Adapts the raw API response to enriched API keys
 * - Filters out revoked keys
 * - Resolves user email from included resources
 * - Co-locates data for better performance
 *
 * @param response - Raw API response with data and included resources
 * @returns Array of enriched API keys ready for UI consumption
 */
export function adaptApiKeysResponse(
  response: ApiKeyResponse | undefined,
): EnrichedApiKey[] {
  if (!response?.data) {
    return [];
  }

  return response.data
    .filter((key) => !key.attributes.revoked)
    .map((key) => ({
      ...key,
      userEmail: getApiKeyUserEmail(key, response.included),
    }));
}
