"use client";

import {
  getLighthouseProviderByType,
  refreshProviderModels,
  testProviderConnection,
} from "@/actions/lighthouse/lighthouse";
import { getTask } from "@/actions/task/tasks";
import { checkTaskStatus } from "@/lib/helper";
import type { LighthouseProvider } from "@/types/lighthouse";

import { getProviderConfig } from "./llm-provider-registry";

export type LLMCredentialsFormData = Record<string, string>;

export const isProviderFormValid = (
  providerType: LighthouseProvider,
  formData: LLMCredentialsFormData,
  isEditMode: boolean = false,
): boolean => {
  const config = getProviderConfig(providerType);

  if (!config) {
    return false;
  }

  if (isEditMode) {
    return true;
  }

  return config.fields
    .filter((field) => field.required)
    .every((field) => formData[field.name]?.trim());
};

export const shouldTestConnection = (
  providerType: LighthouseProvider,
  formData: LLMCredentialsFormData,
): boolean => {
  const config = getProviderConfig(providerType);

  if (!config) {
    return false;
  }

  const testFields = config.fields.filter(
    (field) => field.requiresConnectionTest,
  );

  return testFields.some((field) => formData[field.name]?.trim());
};

/**
 * Triggers a background job to refresh models from the LLM provider's API
 */
export const refreshModelsInBackground = async (
  providerId: string,
): Promise<void> => {
  const modelsResult = await refreshProviderModels(providerId);

  if (modelsResult.errors) {
    throw new Error(
      modelsResult.errors[0]?.detail || "Failed to start model refresh",
    );
  }

  if (!modelsResult.data?.id) {
    throw new Error("Failed to start model refresh");
  }

  // Wait for task to complete
  const modelsStatus = await checkTaskStatus(modelsResult.data.id, 40, 2000);
  if (!modelsStatus.completed) {
    throw new Error(modelsStatus.error || "Model refresh failed");
  }

  // Check final result
  const modelsTask = await getTask(modelsResult.data.id);
  if (modelsTask.data.attributes.result.error) {
    throw new Error(modelsTask.data.attributes.result.error);
  }
};

/**
 * Tests provider connection and refreshes models
 */
export const testAndRefreshModels = async (
  providerId: string,
): Promise<void> => {
  // Test connection
  const connectionResult = await testProviderConnection(providerId);

  if (connectionResult.errors) {
    throw new Error(
      connectionResult.errors[0]?.detail || "Failed to start connection test",
    );
  }

  if (!connectionResult.data?.id) {
    throw new Error("Failed to start connection test");
  }

  const connectionStatus = await checkTaskStatus(connectionResult.data.id);
  if (!connectionStatus.completed) {
    throw new Error(connectionStatus.error || "Connection test failed");
  }

  const connectionTask = await getTask(connectionResult.data.id);
  const { connected, error: connectionError } =
    connectionTask.data.attributes.result;
  if (!connected) {
    throw new Error(connectionError || "Connection test failed");
  }

  // Refresh models
  await refreshModelsInBackground(providerId);
};

/**
 * Gets the provider ID for a given provider type
 * @param providerType - The provider type (e.g., "openai", "anthropic")
 * @returns Promise that resolves with the provider ID
 * @throws Error if provider not found
 */
export const getProviderIdByType = async (
  providerType: LighthouseProvider,
): Promise<string> => {
  const result = await getLighthouseProviderByType(providerType);

  if (result.errors) {
    throw new Error(result.errors[0]?.detail || "Failed to fetch provider");
  }

  if (!result.data?.id) {
    throw new Error("Provider not found");
  }

  return result.data.id;
};
