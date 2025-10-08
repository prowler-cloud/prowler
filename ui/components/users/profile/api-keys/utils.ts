import { formatDistanceToNow } from "date-fns";

import { API_KEY_STATUS, ApiKeyStatus } from "@/types/api-keys";

import { FALLBACK_VALUES } from "./constants";

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
