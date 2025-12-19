/**
 * Shared constants for Lighthouse AI
 * Used by both server-side (API routes) and client-side (components)
 */

export const META_TOOLS = {
  DESCRIBE: "describe_tool",
  EXECUTE: "execute_tool",
} as const;

export type MetaTool = (typeof META_TOOLS)[keyof typeof META_TOOLS];

export const CHAIN_OF_THOUGHT_ACTIONS = {
  PLANNING: "tool_planning",
  START: "tool_start",
  COMPLETE: "tool_complete",
} as const;

export type ChainOfThoughtAction =
  (typeof CHAIN_OF_THOUGHT_ACTIONS)[keyof typeof CHAIN_OF_THOUGHT_ACTIONS];

export const MESSAGE_STATUS = {
  STREAMING: "streaming",
  SUBMITTED: "submitted",
  IDLE: "idle",
} as const;

export type MessageStatus =
  (typeof MESSAGE_STATUS)[keyof typeof MESSAGE_STATUS];

export const MESSAGE_ROLES = {
  USER: "user",
  ASSISTANT: "assistant",
} as const;

export type MessageRole = (typeof MESSAGE_ROLES)[keyof typeof MESSAGE_ROLES];

export const STREAM_EVENT_TYPES = {
  TEXT_START: "text-start",
  TEXT_DELTA: "text-delta",
  TEXT_END: "text-end",
  DATA_CHAIN_OF_THOUGHT: "data-chain-of-thought",
} as const;

export type StreamEventType =
  (typeof STREAM_EVENT_TYPES)[keyof typeof STREAM_EVENT_TYPES];

export const MESSAGE_PART_TYPES = {
  TEXT: "text",
  DATA_CHAIN_OF_THOUGHT: "data-chain-of-thought",
} as const;

export type MessagePartType =
  (typeof MESSAGE_PART_TYPES)[keyof typeof MESSAGE_PART_TYPES];

export const CHAIN_OF_THOUGHT_STATUS = {
  COMPLETE: "complete",
  ACTIVE: "active",
  PENDING: "pending",
} as const;

export type ChainOfThoughtStatus =
  (typeof CHAIN_OF_THOUGHT_STATUS)[keyof typeof CHAIN_OF_THOUGHT_STATUS];

export const LIGHTHOUSE_AGENT_TAG = "lighthouse-agent";

export const STREAM_MESSAGE_ID = "msg-1";

export const ERROR_PREFIX = "[LIGHTHOUSE_ANALYST_ERROR]:";

export const TOOLS_UNAVAILABLE_MESSAGE =
  "\nProwler tools are unavailable. You cannot access cloud accounts or security scan data. If asked about security status or scan results, inform the user that this data is currently inaccessible.\n";
