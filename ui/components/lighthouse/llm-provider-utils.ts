"use client";

import { getProviderConfig } from "./llm-provider-registry";

export type LLMCredentialsFormData = Record<string, string>;

export const isProviderFormValid = (
  providerId: string,
  formData: LLMCredentialsFormData,
  isEditMode: boolean = false,
): boolean => {
  const config = getProviderConfig(providerId);

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
  providerId: string,
  formData: LLMCredentialsFormData,
): boolean => {
  const config = getProviderConfig(providerId);

  if (!config) {
    return false;
  }

  const testFields = config.fields.filter(
    (field) => field.requiresConnectionTest,
  );

  return testFields.some((field) => formData[field.name]?.trim());
};
