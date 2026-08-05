import {
  LIGHTHOUSE_V2_SSE_EVENT,
  type LighthouseV2SSEEvent,
} from "@/app/(prowler)/lighthouse/_types";
import { consumeStepMarkers } from "@/lib/lighthouse/skills/step-markers";

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
  // Skill workflow step that was active when the tool started; lets the
  // progress timeline nest tool chips under their step.
  step?: number;
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
  // Skill-run step tracking: the last [[step:n]] marker seen, and the chunk
  // suffix held back because it may still complete into a marker.
  currentStep: number | null;
  markerCarry: string;
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
    currentStep: null,
    markerCarry: "",
  };
}

export function reduceLighthouseV2Event(
  state: LighthouseV2StreamState,
  event: LighthouseV2SSEEvent,
): LighthouseV2StreamState {
  switch (event.type) {
    case LIGHTHOUSE_V2_SSE_EVENT.MESSAGE_DELTA: {
      // Skill runs announce workflow steps with [[step:n]] markers embedded in
      // the text stream; strip them here so they never render, and remember
      // the highest/latest one for the progress UI.
      const markers = consumeStepMarkers(state.markerCarry, event.content);
      return {
        ...state,
        status: LIGHTHOUSE_V2_STREAM_STATUS.STREAMING,
        assistantText: `${state.assistantText}${markers.text}`,
        activityItems: appendTextActivityItem(
          state.activityItems,
          markers.text,
        ),
        currentStep: markers.steps.at(-1) ?? state.currentStep,
        markerCarry: markers.carry,
      };
    }
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
            ...(state.currentStep !== null ? { step: state.currentStep } : {}),
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
        ...flushMarkerCarry(state),
        status: LIGHTHOUSE_V2_STREAM_STATUS.COMPLETED,
        activeTaskId: null,
        messageId: event.messageId,
      };
    case LIGHTHOUSE_V2_SSE_EVENT.ERROR:
      return {
        ...flushMarkerCarry(state),
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
        ...flushMarkerCarry(state),
        status: LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED,
        activeTaskId: null,
      };
  }
}

// A held-back suffix that never completed into a marker is plain text. Every
// terminal path (end, error, disconnect) must restore it — a disconnected
// stream never replays, so an unflushed carry is silently lost text.
function flushMarkerCarry(
  state: LighthouseV2StreamState,
): LighthouseV2StreamState {
  return {
    ...state,
    assistantText: `${state.assistantText}${state.markerCarry}`,
    activityItems: appendTextActivityItem(
      state.activityItems,
      state.markerCarry,
    ),
    markerCarry: "",
  };
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
