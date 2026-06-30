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

export type LighthouseV2BedrockCredentials =
  | LighthouseV2BedrockAccessKeyCredentials
  | LighthouseV2BedrockApiKeyCredentials;

export type LighthouseV2Credentials =
  | LighthouseV2OpenAICredentials
  | LighthouseV2OpenAICompatibleCredentials
  | LighthouseV2BedrockCredentials;

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

// Provider-keyed input variants: the `providerType` discriminant ties the
// accepted `credentials` shape (and whether `baseUrl` is allowed) to each
// provider, so a mismatched pair fails to type-check at the call site instead
// of slipping past into the adapter/server-action boundary.
export interface LighthouseV2OpenAIConfigurationInput {
  providerType: typeof LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI;
  credentials: LighthouseV2OpenAICredentials;
  baseUrl?: null;
}

export interface LighthouseV2OpenAICompatibleConfigurationInput {
  providerType: typeof LIGHTHOUSE_V2_PROVIDER_TYPE.OPENAI_COMPATIBLE;
  credentials: LighthouseV2OpenAICompatibleCredentials;
  baseUrl: string;
}

export interface LighthouseV2BedrockConfigurationInput {
  providerType: typeof LIGHTHOUSE_V2_PROVIDER_TYPE.BEDROCK;
  credentials: LighthouseV2BedrockCredentials;
  baseUrl?: null;
}

export type LighthouseV2ConfigurationInput =
  | LighthouseV2OpenAIConfigurationInput
  | LighthouseV2OpenAICompatibleConfigurationInput
  | LighthouseV2BedrockConfigurationInput;

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
  name: string;
  maxInputTokens: number | null;
  maxOutputTokens: number | null;
  supportsFunctionCalling: boolean | null;
  supportsVision: boolean | null;
  supportsReasoning: boolean | null;
}
