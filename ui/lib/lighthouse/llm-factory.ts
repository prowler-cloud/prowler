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
      throw new Error("Provider bedrock not yet implemented");

    default:
      throw new Error(`Unknown provider type: ${config.provider}`);
  }
}
