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
  activeTaskId?: string | null;
}

export interface LighthouseV2Part {
  id: string;
  type: LighthouseV2PartType;
  content: unknown;
  toolCallOutcome: string | null;
  insertedAt: string | null;
  updatedAt: string | null;
}

export interface LighthouseV2Message {
  id: string;
  role: LighthouseV2MessageRole;
  model: string | null;
  tokenUsage: unknown;
  insertedAt: string;
  parts: LighthouseV2Part[];
}

export interface LighthouseV2SendMessageInput {
  sessionId: string;
  text: string;
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
