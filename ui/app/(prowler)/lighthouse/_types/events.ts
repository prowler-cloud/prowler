export const LIGHTHOUSE_V2_SSE_EVENT = {
  MESSAGE_DELTA: "message.delta",
  TOOL_CALL_START: "tool_call.start",
  TOOL_CALL_END: "tool_call.end",
  MESSAGE_END: "message.end",
  ERROR: "error",
  DISCONNECT: "disconnect",
} as const;

export type LighthouseV2SSEEventName =
  (typeof LIGHTHOUSE_V2_SSE_EVENT)[keyof typeof LIGHTHOUSE_V2_SSE_EVENT];

export interface LighthouseV2MessageDeltaEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA;
  content: string;
}

export interface LighthouseV2ToolCallStartEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START;
  toolCallId: string;
  toolName: string;
}

export interface LighthouseV2ToolCallEndEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END;
  toolCallId: string;
  outcome: string;
}

export interface LighthouseV2MessageEndEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END;
  messageId: string;
}

export interface LighthouseV2ErrorEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.ERROR;
  code: string;
  detail: string;
}

export interface LighthouseV2DisconnectEvent {
  type: typeof LIGHTHOUSE_V2_SSE_EVENT.DISCONNECT;
}

export type LighthouseV2SSEEvent =
  | LighthouseV2MessageDeltaEvent
  | LighthouseV2ToolCallStartEvent
  | LighthouseV2ToolCallEndEvent
  | LighthouseV2MessageEndEvent
  | LighthouseV2ErrorEvent
  | LighthouseV2DisconnectEvent;
