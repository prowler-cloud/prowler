import { formatDistanceToNow } from "date-fns";

import { FALLBACK_VALUES } from "./constants";
import {
  API_KEY_STATUS,
  ApiKeyData,
  ApiKeyStatus,
  IncludedResource,
  UserData,
} from "./types";

export const getStatusColor = (
  status: ApiKeyStatus,
): "success" | "danger" | "warning" => {
  const colorMap: Record<ApiKeyStatus, "success" | "danger" | "warning"> = {
    [API_KEY_STATUS.ACTIVE]: "success",
    [API_KEY_STATUS.REVOKED]: "danger",
    [API_KEY_STATUS.EXPIRED]: "warning",
  };

  return colorMap[status] || "success";
};

export const getStatusLabel = (status: ApiKeyStatus): string => {
  const labelMap: Record<ApiKeyStatus, string> = {
    [API_KEY_STATUS.ACTIVE]: "Active",
    [API_KEY_STATUS.REVOKED]: "Revoked",
    [API_KEY_STATUS.EXPIRED]: "Expired",
  };

  return labelMap[status] || FALLBACK_VALUES.UNKNOWN;
};

export const formatRelativeTime = (date: string | null): string => {
  if (!date) return FALLBACK_VALUES.NEVER;
  return formatDistanceToNow(new Date(date), { addSuffix: true });
};

export const calculateExpiryDate = (days: number): string => {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + days);
  return expiresAt.toISOString();
};

/**
 * Generic utility to find a resource in the included array by type and ID
 */
export const findIncludedResource = <T extends IncludedResource>(
  included: IncludedResource[] | undefined,
  type: string,
  id: string,
): T | undefined => {
  if (!included) return undefined;
  return included.find(
    (resource): resource is T => resource.type === type && resource.id === id,
  );
};

/**
 * Extracts the email from the included resources based on the API key's entity relationship
 */
export const getApiKeyUserEmail = (
  apiKey: ApiKeyData,
  included?: IncludedResource[],
): string => {
  if (!apiKey.relationships?.entity?.data) {
    return FALLBACK_VALUES.UNKNOWN;
  }

  const userId = apiKey.relationships.entity.data.id;
  const user = findIncludedResource<UserData>(included, "users", userId);

  return user?.attributes.email || FALLBACK_VALUES.UNKNOWN;
};

/**
 * Checks if an API key name already exists in the list
 * @param name - The name to check
 * @param existingApiKeys - List of existing API keys
 * @param excludeId - Optional ID to exclude from the check (for edit scenarios)
 * @returns true if the name already exists, false otherwise
 */
export const isApiKeyNameDuplicate = (
  name: string,
  existingApiKeys: ApiKeyData[],
  excludeId?: string,
): boolean => {
  const trimmedName = name.trim().toLowerCase();

  return existingApiKeys.some(
    (key) =>
      key.id !== excludeId &&
      key.attributes.name?.toLowerCase() === trimmedName,
  );
};
