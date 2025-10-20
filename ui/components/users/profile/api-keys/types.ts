// API Key types following JSON:API specification

export interface ApiKeyAttributes {
  name: string | null;
  prefix: string;
  expires_at: string;
  revoked: boolean;
  inserted_at: string;
  last_used_at: string | null;
}

export interface ApiKeyRelationships {
  entity: {
    data: {
      type: "users";
      id: string;
    } | null;
  };
}

export interface ApiKeyData {
  type: "api-keys";
  id: string;
  attributes: ApiKeyAttributes;
  relationships?: ApiKeyRelationships;
}

// Included resource types
export interface UserAttributes {
  name: string;
  email: string;
  company_name: string;
  date_joined: string;
}

export interface RoleAttributes {
  name: string;
  manage_users: boolean;
  manage_account: boolean;
}

export interface UserData {
  type: "users";
  id: string;
  attributes: UserAttributes;
  relationships?: {
    roles: {
      data: Array<{
        type: "roles";
        id: string;
      }>;
      meta?: {
        count: number;
      };
    };
  };
}

export interface RoleData {
  type: "roles";
  id: string;
  attributes: RoleAttributes;
}

export type IncludedResource = UserData | RoleData;

export interface ApiKeyResponse {
  data: ApiKeyData[];
  included?: IncludedResource[];
  meta?: {
    pagination?: {
      page: number;
      pages: number;
      count: number;
    };
  };
}

/**
 * Enriched API Key with user data already resolved
 * This type extends the base ApiKeyData with additional fields
 * populated from the included resources in the API response
 */
export interface EnrichedApiKey extends ApiKeyData {
  userEmail: string;
}

export interface SingleApiKeyResponse {
  data: ApiKeyData;
}

export interface CreateApiKeyResponse {
  data: ApiKeyData & {
    attributes: ApiKeyAttributes & {
      api_key: string; // Only present on creation
    };
  };
}

export interface CreateApiKeyPayload {
  name: string;
  expires_at?: string; // ISO date string
}

export interface UpdateApiKeyPayload {
  name: string;
}

// Status for UI display
export const API_KEY_STATUS = {
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
} as const;

export type ApiKeyStatus = (typeof API_KEY_STATUS)[keyof typeof API_KEY_STATUS];

// Helper to determine API key status
export const getApiKeyStatus = (apiKey: ApiKeyData): ApiKeyStatus => {
  if (apiKey.attributes.revoked) {
    return API_KEY_STATUS.REVOKED;
  }

  const expiryDate = new Date(apiKey.attributes.expires_at);
  const now = new Date();

  if (expiryDate < now) {
    return API_KEY_STATUS.EXPIRED;
  }

  return API_KEY_STATUS.ACTIVE;
};
