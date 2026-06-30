export const LIGHTHOUSE_V2_PROVIDER_TYPE = {
  OPENAI: "openai",
  BEDROCK: "bedrock",
  OPENAI_COMPATIBLE: "openai-compatible",
} as const;

export type LighthouseV2ProviderType =
  (typeof LIGHTHOUSE_V2_PROVIDER_TYPE)[keyof typeof LIGHTHOUSE_V2_PROVIDER_TYPE];

export interface LighthouseV2OpenAICredentials {
  api_key: string;
}

export interface LighthouseV2OpenAICompatibleCredentials {
  api_key: string;
}

export interface LighthouseV2BedrockAccessKeyCredentials {
  aws_access_key_id: string;
  aws_secret_access_key: string;
  aws_region_name: string;
}

export interface LighthouseV2BedrockApiKeyCredentials {
  api_key: string;
  aws_region_name: string;
}

export type LighthouseV2Credentials =
  | LighthouseV2OpenAICredentials
  | LighthouseV2OpenAICompatibleCredentials
  | LighthouseV2BedrockAccessKeyCredentials
  | LighthouseV2BedrockApiKeyCredentials;

export interface LighthouseV2Configuration {
  id: string;
  providerType: LighthouseV2ProviderType;
  baseUrl: string | null;
  defaultModel: string | null;
  businessContext: string;
  connected: boolean | null;
  connectionLastCheckedAt: string | null;
  insertedAt: string;
  updatedAt: string;
}

export interface LighthouseV2ConfigurationInput {
  providerType: LighthouseV2ProviderType;
  credentials: LighthouseV2Credentials;
  baseUrl?: string | null;
}

export interface LighthouseV2ConfigurationUpdateInput {
  credentials?: LighthouseV2Credentials;
  baseUrl?: string | null;
  defaultModel?: string | null;
  businessContext?: string;
}

export interface LighthouseV2SupportedProvider {
  id: LighthouseV2ProviderType;
  name: string;
}

export interface LighthouseV2SupportedModel {
  id: string;
  maxInputTokens: number | null;
  maxOutputTokens: number | null;
  supportsFunctionCalling: boolean | null;
  supportsVision: boolean | null;
  supportsReasoning: boolean | null;
}
