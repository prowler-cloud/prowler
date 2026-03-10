import {
  AIMessage,
  BaseMessage,
  ChatMessage,
  HumanMessage,
} from "@langchain/core/messages";
import type { UIMessage } from "ai";

import type { ModelParams } from "@/types/lighthouse";

// https://stackoverflow.com/questions/79081298/how-to-stream-langchain-langgraphs-final-generation
/**
 * Converts a Vercel message to a LangChain message.
 * @param message - The message to convert.
 * @returns The converted LangChain message.
 */
export const convertVercelMessageToLangChainMessage = (
  message: UIMessage,
): BaseMessage => {
  // Extract text content from message parts
  const content =
    message.parts
      ?.filter((p) => p.type === "text")
      .map((p) => ("text" in p ? p.text : ""))
      .join("") || "";

  switch (message.role) {
    case "user":
      return new HumanMessage({ content });
    case "assistant":
      return new AIMessage({ content });
    default:
      return new ChatMessage({ content, role: message.role });
  }
};

export const getModelParams = (config: {
  model: string;
  max_tokens?: number;
  temperature?: number;
}): ModelParams => {
  const modelId = config.model;

  const params: ModelParams = {
    maxTokens: config.max_tokens,
    temperature: config.temperature,
    reasoningEffort: undefined,
  };

  if (modelId.startsWith("gpt-5")) {
    params.temperature = undefined;
    params.reasoningEffort = "minimal" as const;
    params.maxTokens = undefined;
  }

  return params;
};
