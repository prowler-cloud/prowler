"use client";

import { Bot, Loader2 } from "lucide-react";

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtStep,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import {
  LIGHTHOUSE_V2_STREAM_STATUS,
  type LighthouseV2StreamState,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import { cn } from "@/lib/utils";

import { MessageMarkdown } from "./message-markdown";

export function StreamingAssistantMessage({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  const hasActivity =
    Boolean(streamState.activeTaskId) || streamState.toolCalls.length > 0;

  return (
    <article className="flex justify-start gap-3">
      <Bot className="text-text-neutral-tertiary mt-1 size-5" />
      <div className="bg-bg-neutral-tertiary text-text-neutral-primary max-w-[min(760px,85%)] rounded-[8px] px-4 py-3 text-sm">
        {hasActivity && <StreamingActivity streamState={streamState} />}
        {streamState.assistantText && (
          <div className={cn(hasActivity && "mt-3")}>
            <MessageMarkdown text={streamState.assistantText} isStreaming />
          </div>
        )}
      </div>
    </article>
  );
}

function StreamingActivity({
  streamState,
}: {
  streamState: LighthouseV2StreamState;
}) {
  const hasAssistantText = Boolean(streamState.assistantText);
  const hasToolCalls = streamState.toolCalls.length > 0;
  const isDisconnected =
    streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED;
  const thinkingStatus =
    hasAssistantText || hasToolCalls ? "complete" : "active";

  return (
    <ChainOfThought className="max-w-none space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary">
        <span className={cn(!isDisconnected && "animate-pulse")}>
          {getActivityHeader(streamState)}
        </span>
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent className="mt-2 space-y-2">
        <ChainOfThoughtStep
          label="Preparing response"
          status={thinkingStatus}
        />
        {isDisconnected && (
          <ChainOfThoughtStep label="Reconnecting stream" status="active" />
        )}
        {streamState.toolCalls.map((toolCall) => (
          <ChainOfThoughtStep
            key={toolCall.id}
            description={
              toolCall.outcome && toolCall.outcome.toLowerCase() !== "success"
                ? toolCall.outcome
                : undefined
            }
            icon={toolCall.status === "running" ? Loader2 : undefined}
            label={getToolCallLabel(toolCall)}
            status={toolCall.status === "running" ? "active" : "complete"}
          />
        ))}
      </ChainOfThoughtContent>
    </ChainOfThought>
  );
}

function getActivityHeader(streamState: LighthouseV2StreamState): string {
  if (streamState.status === LIGHTHOUSE_V2_STREAM_STATUS.DISCONNECTED) {
    return "Reconnecting";
  }
  if (streamState.toolCalls.some((toolCall) => toolCall.status === "running")) {
    return "Using tools";
  }
  return "Thinking";
}

function getToolCallLabel(
  toolCall: LighthouseV2StreamState["toolCalls"][number],
): string {
  return `${toolCall.status === "running" ? "Calling" : "Called"} ${
    toolCall.name
  }`;
}
