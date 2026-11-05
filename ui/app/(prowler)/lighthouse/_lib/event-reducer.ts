import {
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2SSEEvent,
} from "@/app/(prowler)/lighthouse/_types";

export const LIGHTHOUSE_V2_STREAM_STATUS = {
  IDLE: "idle",
  STREAMING: "streaming",
  COMPLETED: "completed",
  ERROR: "error",
  DISCONNECTED: "disconnected",
} as const;

export type LighthouseV2StreamStatus =
  (typeof LIGHTHOUSE_V2_STREAM_STATUS)[keyof typeof LIGHTHOUSE_V2_STREAM_STATUS];

export const LIGHTHOUSE_V2_TOOL_CALL_STATUS = {
  RUNNING: "running",
  COMPLETED: "completed",
} as const;

export type LighthouseV2ToolCallStatus =
  (typeof LIGHTHOUSE_V2_TOOL_CALL_STATUS)[keyof typeof LIGHTHOUSE_V2_TOOL_CALL_STATUS];

export const LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE = {
  TEXT: "text",
  TOOL_CALL: "tool_call",
} as const;

export interface LighthouseV2ToolCallState {
  id: string;
  name: string;
  status: LighthouseV2ToolCallStatus;
  outcome?: string;
}

export interface LighthouseV2StreamTextActivityItem {
  id: string;
  type: typeof LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT;
  text: string;
}

export interface LighthouseV2StreamToolCallActivityItem
  extends LighthouseV2ToolCallState {
  type: typeof LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TOOL_CALL;
}

export type LighthouseV2StreamActivityItem =
  | LighthouseV2StreamTextActivityItem
  | LighthouseV2StreamToolCallActivityItem;

export interface LighthouseV2StreamError {
  code: string;
  detail: string;
}

export interface LighthouseV2StreamState {
  status: LighthouseV2StreamStatus;
  activeTaskId: string | null;
  assistantText: string;
  toolCalls: LighthouseV2ToolCallState[];
  activityItems: LighthouseV2StreamActivityItem[];
  messageId?: string;
  error?: LighthouseV2StreamError;
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
    activityItems: [],
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
        activityItems: appendTextActivityItem(
          state.activityItems,
          event.content,
        ),
      };
    case LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_START: {
      const toolCall = {
        id: event.toolCallId,
        name: event.toolName,
        status: LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING,
      };
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.STREAMING,
        toolCalls: [...state.toolCalls, toolCall],
        activityItems: [
          ...state.activityItems,
          {
            ...toolCall,
            type: LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TOOL_CALL,
          },
        ],
      };
    }
    case LIGHTHOUSE_V2_SSE_EVENT.TOOL_CALL_END:
      return {
        ...state,
        toolCalls: state.toolCalls.map((toolCall) =>
          toolCall.id === event.toolCallId
            ? {
                ...toolCall,
                status: LIGHTHOUSE_V2_TOOL_CALL_STATUS.COMPLETED,
                outcome: event.outcome,
              }
            : toolCall,
        ),
        activityItems: state.activityItems.map((item) =>
          item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TOOL_CALL &&
          item.id === event.toolCallId
            ? {
                ...item,
                status: LIGHTHOUSE_V2_TOOL_CALL_STATUS.COMPLETED,
                outcome: event.outcome,
              }
            : item,
        ),
      };
    case LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_END:
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.COMPLETED,
        activeTaskId: null,
        messageId: event.messageId,
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
      // Clear the task gate so the UI can recover: keeping activeTaskId set
      // leaves canSend false and makes the Retry button a no-op.
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED,
        activeTaskId: null,
      };
  }
}

function appendTextActivityItem(
  activityItems: LighthouseV2StreamActivityItem[],
  text: string,
): LighthouseV2StreamActivityItem[] {
  if (!text) {
    return activityItems;
  }

  const lastItem = activityItems.at(-1);
  if (lastItem?.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT) {
    return [
      ...activityItems.slice(0, -1),
      {
        ...lastItem,
        text: `${lastItem.text}${text}`,
      },
    ];
  }

  return [
    ...activityItems,
    {
      id: `text-${activityItems.length}`,
      type: LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT,
      text,
    },
  ];
}
