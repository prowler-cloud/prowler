import { ChatBedrockConverse } from "@langchain/aws";
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { ChatOpenAI } from "@langchain/openai";

export type ProviderType = "openai" | "bedrock" | "openai_compatible";

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

export function createLLM(config: LLMConfig): BaseChatModel {
  switch (config.provider) {
    case "openai":
      return new ChatOpenAI({
        modelName: config.model,
        openAIApiKey: config.credentials.api_key,
        streaming: config.streaming,
        tags: config.tags,
        maxTokens: config.modelParams?.maxTokens,
        temperature: config.modelParams?.temperature,
      });

    case "openai_compatible":
      return new ChatOpenAI({
        modelName: config.model,
        openAIApiKey: config.credentials.api_key,
        configuration: {
          baseURL: config.baseUrl,
        },
        streaming: config.streaming,
        tags: config.tags,
        maxTokens: config.modelParams?.maxTokens,
        temperature: config.modelParams?.temperature,
      });

    case "bedrock":
      if (
        !config.credentials.access_key_id ||
        !config.credentials.secret_access_key ||
        !config.credentials.region
      ) {
        throw new Error(
          "Bedrock provider requires access_key_id, secret_access_key, and region",
        );
      }
      return new ChatBedrockConverse({
        model: config.model,
        region: config.credentials.region,
        credentials: {
          accessKeyId: config.credentials.access_key_id,
          secretAccessKey: config.credentials.secret_access_key,
        },
        streaming: config.streaming,
        tags: config.tags,
        maxTokens: config.modelParams?.maxTokens,
        temperature: config.modelParams?.temperature,
      });

    default:
      throw new Error(`Unknown provider type: ${config.provider}`);
  }
}
