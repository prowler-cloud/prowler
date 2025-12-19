/**
 * Utilities for Lighthouse chat message processing
 * Client-side utilities for chat.tsx
 */

import {
  CHAIN_OF_THOUGHT_ACTIONS,
  ERROR_PREFIX,
  MESSAGE_ROLES,
  MESSAGE_STATUS,
  META_TOOLS,
} from "@/lib/lighthouse/constants";
import type { ChainOfThoughtData, Message } from "@/lib/lighthouse/types";

// Re-export constants for convenience
export {
  CHAIN_OF_THOUGHT_ACTIONS,
  ERROR_PREFIX,
  MESSAGE_ROLES,
  MESSAGE_STATUS,
  META_TOOLS,
};

// Re-export types
export type { ChainOfThoughtData as ChainOfThoughtEvent, Message };

/**
 * Extracts text content from a message by filtering and joining text parts
 *
 * @param message - The message to extract text from
 * @returns The concatenated text content
 */
export function extractMessageText(message: Message): string {
  return message.parts
    .filter((p) => p.type === "text")
    .map((p) => (p.text ? p.text : ""))
    .join("");
}

/**
 * Extracts chain-of-thought events from a message
 *
 * @param message - The message to extract events from
 * @returns Array of chain-of-thought events
 */
export function extractChainOfThoughtEvents(
  message: Message,
): ChainOfThoughtData[] {
  return message.parts
    .filter((part) => part.type === "data-chain-of-thought")
    .map((part) => part.data as ChainOfThoughtData);
}

/**
 * Gets the label for a chain-of-thought step based on meta-tool and tool name
 *
 * @param metaTool - The meta-tool name
 * @param tool - The actual tool name
 * @returns A human-readable label for the step
 */
export function getChainOfThoughtStepLabel(
  metaTool: string,
  tool: string | null,
): string {
  if (metaTool === META_TOOLS.DESCRIBE && tool) {
    return `Retrieving ${tool} tool info`;
  }

  if (metaTool === META_TOOLS.EXECUTE && tool) {
    return `Executing ${tool}`;
  }

  return tool || "Completed";
}

/**
 * Determines if a meta-tool is a wrapper tool (describe_tool or execute_tool)
 *
 * @param metaTool - The meta-tool name to check
 * @returns True if it's a meta-tool, false otherwise
 */
export function isMetaTool(metaTool: string): boolean {
  return metaTool === META_TOOLS.DESCRIBE || metaTool === META_TOOLS.EXECUTE;
}

/**
 * Gets the header text for chain-of-thought display
 *
 * @param isStreaming - Whether the message is currently streaming
 * @param events - The chain-of-thought events
 * @returns The header text to display
 */
export function getChainOfThoughtHeaderText(
  isStreaming: boolean,
  events: ChainOfThoughtData[],
): string {
  if (!isStreaming) {
    return "Thought process";
  }

  // Find the last completed tool to show current status
  const lastCompletedEvent = events
    .slice()
    .reverse()
    .find((e) => e.action === CHAIN_OF_THOUGHT_ACTIONS.COMPLETE && e.tool);

  if (lastCompletedEvent?.tool) {
    return `Executing ${lastCompletedEvent.tool}...`;
  }

  return "Processing...";
}
