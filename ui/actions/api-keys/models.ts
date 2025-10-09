import { ApiKeyData } from "@/components/users/profile/api-keys/types";

/**
 * Enriched API Key with user data already resolved
 * This type extends the base ApiKeyData with additional fields
 * populated from the included resources in the API response
 */
export interface EnrichedApiKey extends ApiKeyData {
  userEmail: string;
}
