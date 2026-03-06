/**
 * Utilities for handling Lighthouse analyst stream events
 * Server-side only (used in API routes)
 */

import {
  CHAIN_OF_THOUGHT_ACTIONS,
  type ChainOfThoughtAction,
  ERROR_PREFIX,
  LIGHTHOUSE_AGENT_TAG,
  META_TOOLS,
  STREAM_MESSAGE_ID,
} from "@/lib/lighthouse/constants";
import type { ChainOfThoughtData, StreamEvent } from "@/lib/lighthouse/types";

// Re-export for convenience
export { CHAIN_OF_THOUGHT_ACTIONS, ERROR_PREFIX, STREAM_MESSAGE_ID };

/**
 * Extracts the actual tool name from meta-tool input.
 *
 * Meta-tools (describe_tool, execute_tool) wrap actual tool calls.
 * This function parses the input to extract the real tool name.
 *
 * @param metaToolName - The name of the meta-tool or actual tool
 * @param toolInput - The input data for the tool
 * @returns The actual tool name, or null if it cannot be determined
 */
export function extractActualToolName(
  metaToolName: string,
  toolInput: unknown,
): string | null {
  // Check if this is a meta-tool
  if (
    metaToolName === META_TOOLS.DESCRIBE ||
    metaToolName === META_TOOLS.EXECUTE
  ) {
    // Meta-tool: Parse the JSON string in input.input
    try {
      if (
        toolInput &&
        typeof toolInput === "object" &&
        "input" in toolInput &&
        typeof toolInput.input === "string"
      ) {
        const parsedInput = JSON.parse(toolInput.input);
        return parsedInput.toolName || null;
      }
    } catch {
      // Failed to parse, return null
      return null;
    }
  }

  // Actual tool execution: use the name directly
  return metaToolName;
}

/**
 * Creates a text-start event
 */
export function createTextStartEvent(messageId: string): StreamEvent {
  return {
    type: "text-start",
    id: messageId,
  };
}

/**
 * Creates a text-delta event
 */
export function createTextDeltaEvent(
  messageId: string,
  delta: string,
): StreamEvent {
  return {
    type: "text-delta",
    id: messageId,
    delta,
  };
}

/**
 * Creates a text-end event
 */
export function createTextEndEvent(messageId: string): StreamEvent {
  return {
    type: "text-end",
    id: messageId,
  };
}

/**
 * Creates a chain-of-thought event
 */
export function createChainOfThoughtEvent(
  data: ChainOfThoughtData,
): StreamEvent {
  return {
    type: "data-chain-of-thought",
    data,
  };
}

// Event Handler Types
interface StreamController {
  enqueue: (event: StreamEvent) => void;
}

interface ChatModelStreamData {
  chunk?: {
    content?: string | unknown;
  };
}

interface ChatModelEndData {
  output?: {
    tool_calls?: Array<{
      id: string;
      name: string;
      args: Record<string, unknown>;
    }>;
  };
}

/**
 * Handles chat model stream events - processes token-by-token text streaming
 *
 * @param controller - The ReadableStream controller
 * @param data - The event data containing the chunk
 * @param tags - Tags associated with the event
 * @returns True if the event was handled and should mark stream as started
 */
export function handleChatModelStreamEvent(
  controller: StreamController,
  data: ChatModelStreamData,
  tags: string[] | undefined,
): boolean {
  if (data.chunk?.content && tags && tags.includes(LIGHTHOUSE_AGENT_TAG)) {
    const content =
      typeof data.chunk.content === "string" ? data.chunk.content : "";

    if (content) {
      controller.enqueue(createTextDeltaEvent(STREAM_MESSAGE_ID, content));
      return true;
    }
  }
  return false;
}

/**
 * Handles chat model end events - detects and emits tool planning events
 *
 * @param controller - The ReadableStream controller
 * @param data - The event data containing AI message output
 */
export function handleChatModelEndEvent(
  controller: StreamController,
  data: ChatModelEndData,
): void {
  const aiMessage = data?.output;

  if (
    aiMessage &&
    typeof aiMessage === "object" &&
    "tool_calls" in aiMessage &&
    Array.isArray(aiMessage.tool_calls) &&
    aiMessage.tool_calls.length > 0
  ) {
    // Emit data annotation for tool planning
    for (const toolCall of aiMessage.tool_calls) {
      const metaToolName = toolCall.name;
      const toolArgs = toolCall.args;

      // Extract actual tool name from toolArgs.toolName (camelCase)
      const actualToolName =
        toolArgs && typeof toolArgs === "object" && "toolName" in toolArgs
          ? (toolArgs.toolName as string)
          : null;

      controller.enqueue(
        createChainOfThoughtEvent({
          action: CHAIN_OF_THOUGHT_ACTIONS.PLANNING,
          metaTool: metaToolName,
          tool: actualToolName,
          toolCallId: toolCall.id,
        }),
      );
    }
  }
}

/**
 * Handles tool start/end events - emits chain-of-thought events for tool execution
 *
 * @param controller - The ReadableStream controller
 * @param action - The action type (START or COMPLETE)
 * @param name - The name of the tool
 * @param toolInput - The input data for the tool
 */
export function handleToolEvent(
  controller: StreamController,
  action: ChainOfThoughtAction,
  name: string | undefined,
  toolInput: unknown,
): void {
  const metaToolName = typeof name === "string" ? name : "unknown";
  const actualToolName = extractActualToolName(metaToolName, toolInput);

  controller.enqueue(
    createChainOfThoughtEvent({
      action,
      metaTool: metaToolName,
      tool: actualToolName,
    }),
  );
}
