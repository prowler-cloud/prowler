import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";

import type { LighthouseV2ProviderType } from "./config";

export const LIGHTHOUSE_V2_MESSAGE_ROLE = {
  USER: "user",
  ASSISTANT: "assistant",
} as const;

export type LighthouseV2MessageRole =
  (typeof LIGHTHOUSE_V2_MESSAGE_ROLE)[keyof typeof LIGHTHOUSE_V2_MESSAGE_ROLE];

export const LIGHTHOUSE_V2_PART_TYPE = {
  TEXT: "text",
  REASONING: "reasoning",
  TOOL_CALL: "tool_call",
} as const;

export type LighthouseV2PartType =
  (typeof LIGHTHOUSE_V2_PART_TYPE)[keyof typeof LIGHTHOUSE_V2_PART_TYPE];

export interface LighthouseV2Session {
  id: string;
  title: string | null;
  isArchived: boolean;
  insertedAt: string;
  updatedAt: string;
}

export interface LighthouseV2Part {
  id: string;
  type: LighthouseV2PartType;
  content: unknown;
  toolCallOutcome: string | null;
  insertedAt: string | null;
  updatedAt: string | null;
}

export const LIGHTHOUSE_V2_RUN_STATUS = {
  QUEUED: "queued",
  RUNNING: "running",
  COMPLETED: "completed",
  BLOCKED: "blocked",
  FAILED: "failed",
  CANCELLED: "cancelled",
} as const;

export type LighthouseV2RunStatus =
  (typeof LIGHTHOUSE_V2_RUN_STATUS)[keyof typeof LIGHTHOUSE_V2_RUN_STATUS];

export const LIGHTHOUSE_V2_FEEDBACK_RATING = {
  UP: "up",
  DOWN: "down",
} as const;

export type LighthouseV2FeedbackRating =
  (typeof LIGHTHOUSE_V2_FEEDBACK_RATING)[keyof typeof LIGHTHOUSE_V2_FEEDBACK_RATING];

export interface LighthouseV2Run {
  id: string;
  status: LighthouseV2RunStatus;
  terminalCode: string | null;
  hasAssistantMessage: boolean;
  feedbackRating: LighthouseV2FeedbackRating | null;
}

// Normalized shape of a TOOL_CALL part's `content`. The backend persists this
// blob in snake_case (tool_call_id, tool_name, ...); `getToolCallContent`
// maps it to this camelCase form so the UI never touches the raw keys.
export interface LighthouseV2ToolCallContent {
  toolCallId: string;
  toolName: string;
  arguments: unknown;
  result: unknown;
  outcome: string | null;
}

export interface LighthouseV2Message {
  id: string;
  role: LighthouseV2MessageRole;
  model: string | null;
  tokenUsage: unknown;
  insertedAt: string;
  parts: LighthouseV2Part[];
  run?: LighthouseV2Run | null;
}

export interface LighthouseV2RunFeedbackInput {
  sessionId: string;
  runId: string;
  rating: LighthouseV2FeedbackRating;
  idempotencyKey: string;
}

export interface LighthouseV2SendMessageInput {
  sessionId: string;
  displayText: string;
  context?: LighthouseContextEnvelope;
  provider: LighthouseV2ProviderType;
  model?: string | null;
}

export const LIGHTHOUSE_V2_TASK_STATE = {
  AVAILABLE: "available",
  EXECUTING: "executing",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
} as const;

export type LighthouseV2TaskState =
  (typeof LIGHTHOUSE_V2_TASK_STATE)[keyof typeof LIGHTHOUSE_V2_TASK_STATE];

export interface LighthouseV2Task {
  id: string;
  name: string | null;
  state: LighthouseV2TaskState | string;
  insertedAt?: string;
  completedAt?: string | null;
  metadata?: unknown;
  result?: unknown;
}

export interface LighthouseV2SendMessageResult {
  task: LighthouseV2Task;
}
