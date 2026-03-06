/**
 * Shared types for Lighthouse AI
 * Used by both server-side (API routes) and client-side (components)
 */

import type {
  ChainOfThoughtAction,
  StreamEventType,
} from "@/lib/lighthouse/constants";

export interface ChainOfThoughtData {
  action: ChainOfThoughtAction;
  metaTool: string;
  tool: string | null;
  toolCallId?: string;
}

export interface StreamEvent {
  type: StreamEventType;
  id?: string;
  delta?: string;
  data?: ChainOfThoughtData;
}

/**
 * Base message part interface
 * Compatible with AI SDK's UIMessagePart types
 * Note: `data` is typed as `unknown` for compatibility with AI SDK
 */
export interface MessagePart {
  type: string;
  text?: string;
  data?: unknown;
}

/**
 * Chat message interface
 * Compatible with AI SDK's UIMessage type
 */
export interface Message {
  id: string;
  role: "user" | "assistant" | "system";
  parts: MessagePart[];
}
