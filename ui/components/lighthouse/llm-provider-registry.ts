"use client";

export type LLMProviderFieldType = "text" | "password";

export interface LLMProviderField {
  name: string;
  type: LLMProviderFieldType;
  label: string;
  placeholder: string;
  required: boolean;
  collapsible?: boolean;
  requiresConnectionTest?: boolean;
}

export interface LLMProviderConfig {
  id: string;
  name: string;
  description: string;
  icon: string;
  fields: LLMProviderField[];
}
export const LLM_PROVIDER_REGISTRY: Record<string, LLMProviderConfig> = {
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
      {
        name: "base_url",
        type: "text",
        label: "Base URL",
        placeholder: "https://api.openai.com/v1",
        required: false,
        collapsible: true,
        requiresConnectionTest: false,
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
  providerId: string,
): LLMProviderConfig | undefined => {
  return LLM_PROVIDER_REGISTRY[providerId];
};

export const getAllProviders = (): LLMProviderConfig[] => {
  return Object.values(LLM_PROVIDER_REGISTRY);
};

export const getMainFields = (providerId: string): LLMProviderField[] => {
  const config = getProviderConfig(providerId);
  return config?.fields.filter((field) => !field.collapsible) ?? [];
};

export const getCollapsibleFields = (
  providerId: string,
): LLMProviderField[] => {
  const config = getProviderConfig(providerId);
  return config?.fields.filter((field) => field.collapsible) ?? [];
};

export const hasCollapsibleFields = (providerId: string): boolean => {
  return getCollapsibleFields(providerId).length > 0;
};
