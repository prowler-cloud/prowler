"use client";

import type { LighthouseProvider } from "@/types/lighthouse";

export type LLMProviderFieldType = "text" | "password";

export interface LLMProviderField {
  name: string;
  type: LLMProviderFieldType;
  label: string;
  placeholder: string;
  required: boolean;
  requiresConnectionTest?: boolean;
}

export interface LLMProviderConfig {
  id: LighthouseProvider;
  name: string;
  description: string;
  icon: string;
  fields: LLMProviderField[];
}

export const LLM_PROVIDER_REGISTRY: Record<
  LighthouseProvider,
  LLMProviderConfig
> = {
  openai: {
    id: "openai",
    name: "OpenAI",
    description: "Industry-leading GPT models for general-purpose AI",
    icon: "simple-icons:openai",
    fields: [
      {
        name: "api_key",
        type: "password",
        label: "API Key",
        placeholder: "Enter your API key",
        required: true,
        requiresConnectionTest: true,
      },
    ],
  },
  bedrock: {
    id: "bedrock",
    name: "Amazon Bedrock",
    description: "AWS-managed AI with Claude, Llama, Titan & more",
    icon: "simple-icons:amazonwebservices",
    fields: [
      {
        name: "access_key_id",
        type: "text",
        label: "AWS Access Key ID",
        placeholder: "Enter the AWS Access Key ID",
        required: true,
        requiresConnectionTest: true,
      },
      {
        name: "secret_access_key",
        type: "password",
        label: "AWS Secret Access Key",
        placeholder: "Enter the AWS Secret Access Key",
        required: true,
        requiresConnectionTest: true,
      },
      {
        name: "region",
        type: "text",
        label: "AWS Region",
        placeholder: "Enter the AWS Region",
        required: true,
        requiresConnectionTest: true,
      },
    ],
  },
  openai_compatible: {
    id: "openai_compatible",
    name: "OpenAI Compatible",
    description: "Connect to custom OpenAI-compatible endpoints",
    icon: "simple-icons:openai",
    fields: [
      {
        name: "api_key",
        type: "password",
        label: "API Key",
        placeholder: "Enter your API key",
        required: true,
        requiresConnectionTest: true,
      },
      {
        name: "base_url",
        type: "text",
        label: "Base URL",
        placeholder: "https://openrouter.ai/api/v1",
        required: true,
        requiresConnectionTest: false,
      },
    ],
  },
};

export const getProviderConfig = (
  providerType: LighthouseProvider,
): LLMProviderConfig | undefined => {
  return LLM_PROVIDER_REGISTRY[providerType];
};

export const getAllProviders = (): LLMProviderConfig[] => {
  return Object.values(LLM_PROVIDER_REGISTRY);
};

export const getMainFields = (
  providerType: LighthouseProvider,
): LLMProviderField[] => {
  const config = getProviderConfig(providerType);
  return config?.fields ?? [];
};
