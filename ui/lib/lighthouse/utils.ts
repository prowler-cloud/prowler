import {
  AIMessage,
  BaseMessage,
  ChatMessage,
  HumanMessage,
} from "@langchain/core/messages";
import type { Message } from "ai";

// https://stackoverflow.com/questions/79081298/how-to-stream-langchain-langgraphs-final-generation
/**
 * Converts a Vercel message to a LangChain message.
 * @param message - The message to convert.
 * @returns The converted LangChain message.
 */
export const convertVercelMessageToLangChainMessage = (
  message: Message,
): BaseMessage => {
  switch (message.role) {
    case "user":
      return new HumanMessage({ content: message.content });
    case "assistant":
      return new AIMessage({ content: message.content });
    default:
      return new ChatMessage({ content: message.content, role: message.role });
  }
};

/**
 * Converts a LangChain message to a Vercel message.
 * @param message - The message to convert.
 * @returns The converted Vercel message.
 */
export const convertLangChainMessageToVercelMessage = (
  message: BaseMessage,
) => {
  switch (message.getType()) {
    case "human":
      return { content: message.content, role: "user" };
    case "ai":
      return {
        content: message.content,
        role: "assistant",
        tool_calls: (message as AIMessage).tool_calls,
      };
    default:
      return { content: message.content, role: message.getType() };
  }
};
