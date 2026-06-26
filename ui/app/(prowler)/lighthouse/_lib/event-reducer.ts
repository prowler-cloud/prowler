import {
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2SSEEvent,
} from "@/app/(prowler)/lighthouse/_types";

export const LIGHTHOUSE_V2_STREAM_STATUS = {
  IDLE: "idle",
  STREAMING: "streaming",
  COMPLETED: "completed",
  CANCELLED: "cancelled",
  ERROR: "error",
  DISCONNECTED: "disconnected",
} as const;

export type LighthouseV2StreamStatus =
  (typeof LIGHTHOUSE_V2_STREAM_STATUS)[keyof typeof LIGHTHOUSE_V2_STREAM_STATUS];

export interface LighthouseV2ToolCallState {
  id: string;
  name: string;
  status: "running" | "completed";
  outcome?: string;
}

export interface LighthouseV2StreamState {
  status: LighthouseV2StreamStatus;
  activeTaskId: string | null;
  assistantText: string;
  toolCalls: LighthouseV2ToolCallState[];
  messageId?: string;
  error?: {
    code: string;
    detail: string;
  };
}

export function createInitialLighthouseV2StreamState(
  taskId: string | null = null,
): LighthouseV2StreamState {
  return {
    status: taskId
      ? LIGHTHOUSE_V2_STREAM_STATUS.STREAMING
      : LIGHTHOUSE_V2_STREAM_STATUS.IDLE,
    activeTaskId: taskId,
    assistantText: "",
    toolCalls: [],
  };
}

export function reduceLighthouseV2Event(
  state: LighthouseV2StreamState,
  event: LighthouseV2SSEEvent,
): LighthouseV2StreamState {
  switch (event.type) {
    case LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.STREAMING,
        assistantText: `${state.assistantText}${event.content}`,
      };
    case LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.STREAMING,
        toolCalls: [
          ...state.toolCalls,
          {
            id: event.toolCallId,
            name: event.toolName,
            status: "running",
          },
        ],
      };
    case LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END:
      return {
        ...state,
        toolCalls: state.toolCalls.map((toolCall) =>
          toolCall.id === event.toolCallId
            ? {
                ...toolCall,
                status: "completed",
                outcome: event.outcome,
              }
            : toolCall,
        ),
      };
    case LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.COMPLETED,
        activeTaskId: null,
        messageId: event.messageId,
      };
    case LIGHTHOUSE_V2_SSE_EVENT.RUN_CANCELLED:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.CANCELLED,
        activeTaskId: null,
      };
    case LIGHTHOUSE_V2_SSE_EVENT.ERROR:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.ERROR,
        activeTaskId: null,
        error: {
          code: event.code,
          detail: event.detail,
        },
      };
    case LIGHTHOUSE_V2_SSE_EVENT.DISCONNECT:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED,
      };
  }
}
