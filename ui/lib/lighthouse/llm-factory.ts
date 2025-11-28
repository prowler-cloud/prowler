import { BedrockRuntimeClient } from "@aws-sdk/client-bedrock-runtime";
import { ChatBedrockConverse } from "@langchain/aws";
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { ChatOpenAI } from "@langchain/openai";

const PROVIDER_TYPES = {
  OPENAI: "openai",
  BEDROCK: "bedrock",
  OPENAI_COMPATIBLE: "openai_compatible",
} as const;

export type ProviderType = (typeof PROVIDER_TYPES)[keyof typeof PROVIDER_TYPES];

export interface LLMCredentials {
  api_key?: string;
  access_key_id?: string;
  secret_access_key?: string;
  region?: string;
}

export interface LLMConfig {
  provider: ProviderType;
  model: string;
  credentials: LLMCredentials;
  baseUrl?: string;
  streaming?: boolean;
  tags?: string[];
  modelParams?: {
    maxTokens?: number;
    temperature?: number;
    reasoningEffort?: string;
  };
}

function createBedrockClient(
  credentials: LLMCredentials,
): BedrockRuntimeClient {
  if (!credentials.region) {
    throw new Error("Bedrock provider requires region");
  }

  if (credentials.api_key) {
    return new BedrockRuntimeClient({
      region: credentials.region,
      token: async () => ({ token: credentials.api_key as string }),
      authSchemePreference: ["httpBearerAuth"],
    });
  }

  if (!credentials.access_key_id || !credentials.secret_access_key) {
    throw new Error(
      "Bedrock provider requires either api_key or access_key_id and secret_access_key",
    );
  }

  return new BedrockRuntimeClient({
    region: credentials.region,
    credentials: {
      accessKeyId: credentials.access_key_id,
      secretAccessKey: credentials.secret_access_key,
    },
  });
}

function createBedrockLLM(config: LLMConfig): ChatBedrockConverse {
  const client = createBedrockClient(config.credentials);

  return new ChatBedrockConverse({
    model: config.model,
    client,
    region: config.credentials.region!,
    streaming: config.streaming,
    tags: config.tags,
    maxTokens: config.modelParams?.maxTokens,
    temperature: config.modelParams?.temperature,
  });
}

export function createLLM(config: LLMConfig): BaseChatModel {
  switch (config.provider) {
    case PROVIDER_TYPES.OPENAI:
      return new ChatOpenAI({
        modelName: config.model,
        apiKey: config.credentials.api_key,
        streaming: config.streaming,
        tags: config.tags,
        maxTokens: config.modelParams?.maxTokens,
        temperature: config.modelParams?.temperature,
      });

    case PROVIDER_TYPES.OPENAI_COMPATIBLE:
      return new ChatOpenAI({
        modelName: config.model,
        apiKey: config.credentials.api_key,
        configuration: {
          baseURL: config.baseUrl,
        },
        streaming: config.streaming,
        tags: config.tags,
        maxTokens: config.modelParams?.maxTokens,
        temperature: config.modelParams?.temperature,
      });

    case PROVIDER_TYPES.BEDROCK:
      return createBedrockLLM(config);

    default:
      throw new Error(`Unknown provider type: ${config.provider}`);
  }
}
