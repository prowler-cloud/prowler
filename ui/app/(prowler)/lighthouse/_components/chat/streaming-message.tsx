"use client";

import { Bot, Loader2 } from "lucide-react";

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtStep,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import {
  LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE,
  LIGHTHOUSE_V2_STREAM_STATUS,
  LIGHTHOUSE_V2_TOOL_CALL_STATUS,
  type LighthouseV2StreamActivityItem,
  type LighthouseV2StreamState,
  type LighthouseV2StreamToolCallActivityItem,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import { formatToolName } from "@/app/(prowler)/lighthouse/_lib/tool-calls";
import { cn } from "@/lib/utils";

import { MessageMarkdown } from "./message-markdown";

const STREAMING_ACTIVITY_GROUP_TYPE = {
  TEXT: "text",
  TOOL_CALL: "tool_call",
} as const;

interface StreamingTextActivityGroup {
  id: string;
  type: typeof STREAMING_ACTIVITY_GROUP_TYPE.TEXT;
  text: string;
}

interface StreamingToolCallActivityGroup {
  id: string;
  type: typeof STREAMING_ACTIVITY_GROUP_TYPE.TOOL_CALL;
  toolCalls: LighthouseV2StreamToolCallActivityItem[];
}

type StreamingActivityGroup =
  | StreamingTextActivityGroup
  | StreamingToolCallActivityGroup;

export function StreamingAssistantMessage({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  const hasActivity =
    Boolean(streamState.activeTaskId) || streamState.toolCalls.length > 0;

  return (
    <article className="flex min-w-0 justify-start gap-3">
      <Bot className="text-text-neutral-tertiary mt-1 size-5" />
      <div className="bg-bg-neutral-tertiary text-text-neutral-primary max-w-[min(760px,85%)] min-w-0 rounded-[8px] px-4 py-3 text-sm">
        {streamState.activityItems.length > 0 ? (
          <StreamingActivityGroups streamState={streamState} />
        ) : (
          hasActivity && <StreamingPendingActivity streamState={streamState} />
        )}
      </div>
    </article>
  );
}

function StreamingActivityGroups({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  const groups = groupStreamingActivityItems(streamState.activityItems);
  const isDisconnected =
    streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED;

  return (
    <div className="min-w-0 space-y-3">
      {groups.map((group) =>
        group.type === STREAMING_ACTIVITY_GROUP_TYPE.TOOL_CALL ? (
          <StreamingToolCallGroup key={group.id} toolCalls={group.toolCalls} />
        ) : (
          <MessageMarkdown key={group.id} text={group.text} isStreaming />
        ),
      )}
      {isDisconnected && <StreamingReconnectActivity />}
    </div>
  );
}

function StreamingPendingActivity({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  const isDisconnected =
    streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED;

  return (
    <ChainOfThought className="max-w-none space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary">
        <span className={cn(!isDisconnected && "animate-pulse")}>
          {getActivityHeader(streamState)}
        </span>
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent className="mt-2 space-y-2">
        <ChainOfThoughtStep label="Preparing response" status="active" />
        {isDisconnected && (
          <ChainOfThoughtStep label="Reconnecting stream" status="active" />
        )}
      </ChainOfThoughtContent>
    </ChainOfThought>
  );
}

function StreamingToolCallGroup({
  toolCalls,
}: {
  toolCalls: LighthouseV2StreamToolCallActivityItem[];
}) {
  return (
    <ChainOfThought className="max-w-none space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary">
        <span className={cn(hasRunningToolCall(toolCalls) && "animate-pulse")}>
          {getToolActivityHeader(toolCalls)}
        </span>
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent className="mt-2 space-y-2">
        {toolCalls.map((toolCall) => (
          <ChainOfThoughtStep
            key={toolCall.id}
            description={
              toolCall.outcome && toolCall.outcome.toLowerCase() !== "success"
                ? toolCall.outcome
                : undefined
            }
            icon={
              toolCall.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING
                ? Loader2
                : undefined
            }
            label={getToolCallLabel(toolCall)}
            status={
              toolCall.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING
                ? "active"
                : "complete"
            }
          />
        ))}
      </ChainOfThoughtContent>
    </ChainOfThought>
  );
}

function StreamingReconnectActivity() {
  return (
    <ChainOfThought className="max-w-none space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary">
        <span className="animate-pulse">Reconnecting</span>
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent className="mt-2 space-y-2">
        <ChainOfThoughtStep label="Reconnecting stream" status="active" />
      </ChainOfThoughtContent>
    </ChainOfThought>
  );
}

function getActivityHeader(streamState: LighthouseV2StreamState): string {
  if (streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED) {
    return "Reconnecting";
  }
  return "Thinking";
}

function getToolCallLabel(
  toolCall: LighthouseV2StreamToolCallActivityItem,
): string {
  return `${toolCall.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING ? "Calling" : "Called"} ${formatToolName(toolCall.name)}`;
}

function getToolActivityHeader(
  toolCalls: LighthouseV2StreamToolCallActivityItem[],
): string {
  if (toolCalls.length === 1) {
    return getToolCallLabel(toolCalls[0]);
  }

  return hasRunningToolCall(toolCalls) ? "Using tools" : "Used tools";
}

function hasRunningToolCall(
  toolCalls: LighthouseV2StreamToolCallActivityItem[],
): boolean {
  return toolCalls.some(
    (toolCall) => toolCall.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING,
  );
}

function groupStreamingActivityItems(
  activityItems: LighthouseV2StreamActivityItem[],
): StreamingActivityGroup[] {
  return activityItems.reduce<StreamingActivityGroup[]>((groups, item) => {
    const lastGroup = groups.at(-1);

    if (item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT) {
      if (lastGroup?.type === STREAMING_ACTIVITY_GROUP_TYPE.TEXT) {
        return [
          ...groups.slice(0, -1),
          {
            ...lastGroup,
            text: `${lastGroup.text}${item.text}`,
          },
        ];
      }

      return [
        ...groups,
        {
          id: item.id,
          type: STREAMING_ACTIVITY_GROUP_TYPE.TEXT,
          text: item.text,
        },
      ];
    }

    if (lastGroup?.type === STREAMING_ACTIVITY_GROUP_TYPE.TOOL_CALL) {
      return [
        ...groups.slice(0, -1),
        {
          ...lastGroup,
          toolCalls: [...lastGroup.toolCalls, item],
        },
      ];
    }

    return [
      ...groups,
      {
        id: item.id,
        type: STREAMING_ACTIVITY_GROUP_TYPE.TOOL_CALL,
        toolCalls: [item],
      },
    ];
  }, []);
}
