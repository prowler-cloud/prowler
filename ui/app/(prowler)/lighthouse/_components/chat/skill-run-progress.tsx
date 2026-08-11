"use client";

import { Bot, ChevronDown } from "lucide-react";
import { useState, useSyncExternalStore } from "react";

import {
  CHAIN_OF_THOUGHT_STATUS,
  ChainOfThoughtStep,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import {
  LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE,
  LIGHTHOUSE_V2_TOOL_CALL_STATUS,
  type LighthouseV2StreamState,
  type LighthouseV2StreamToolCallActivityItem,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import { formatToolName } from "@/app/(prowler)/lighthouse/_lib/tool-calls";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { cn } from "@/lib/utils";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { StreamingActivityGroups } from "./streaming-message";

interface SkillRunProgressProps {
  skill: LighthouseSkillDefinition;
  streamState: LighthouseV2StreamState;
  startedAt?: string;
}

// Streaming view of a skill run. An LLM run is not deterministic, so there is
// no plan checklist and no percent bar — the card reports observed activity:
// collapsed, a pulsing lighthouse-gradient label naming the tool currently
// running (or the skill itself between tools); expanded, the append-only
// timeline of tool calls as they actually happened. Below, narration and tool
// activity stream interleaved in order, matching the persisted rendering.
export function SkillRunProgress({
  skill,
  streamState,
  startedAt,
}: SkillRunProgressProps) {
  // Local state needed: the user toggles between compact card and timeline.
  const [expanded, setExpanded] = useState(false);
  const toolCallItems = streamState.activityItems.filter(isToolCallItem);
  const lastToolCall = toolCallItems.at(-1);
  // Between tools the model is generating text; naming the skill here would
  // just repeat the card title, so the label reads "Thinking…" instead.
  const activityLabel =
    lastToolCall?.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING
      ? `Running ${formatToolName(lastToolCall.name)}…`
      : "Thinking…";
  // Gate the body on narration: before the first text delta the card's own
  // status label already reports the tool activity, so an items-only body
  // would just duplicate it.
  const hasNarration = streamState.activityItems.some(
    (item) => item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT,
  );
  const Icon = skill.icon;

  return (
    <article className="flex min-w-0 justify-start gap-3">
      <Bot className="text-text-neutral-tertiary mt-1 size-5" />
      <div className="flex max-w-[min(760px,85%)] min-w-0 flex-1 flex-col gap-3">
        <div className="bg-lighthouse rounded-lg p-px">
          <div className="bg-bg-neutral-primary flex flex-col gap-2 rounded-[7px] px-3.5 py-2.5">
            <button
              type="button"
              onClick={() => setExpanded((current) => !current)}
              aria-expanded={expanded}
              className="flex w-full items-center gap-2.5 text-left"
            >
              <Icon
                className="text-text-lighthouse size-4 shrink-0"
                aria-hidden
              />
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="text-text-neutral-primary truncate text-sm font-medium">
                  {skill.name}
                </span>
                <span className="text-text-neutral-secondary truncate text-xs">
                  Running skill
                  <ElapsedTime startedAt={startedAt} />
                </span>
              </span>
              <ChevronDown
                className={cn(
                  "text-text-neutral-tertiary size-4 shrink-0 transition-transform",
                  expanded && "rotate-180",
                )}
                aria-hidden
              />
            </button>
            {expanded ? (
              <SkillToolTimeline toolCallItems={toolCallItems} />
            ) : (
              <span
                role="status"
                className="bg-lighthouse animate-pulse truncate bg-clip-text text-xs font-medium text-transparent"
              >
                {activityLabel}
              </span>
            )}
          </div>
        </div>
        {hasNarration && (
          <div className="bg-bg-neutral-tertiary text-text-neutral-primary max-w-full min-w-0 rounded-[8px] px-4 py-3 text-sm">
            <StreamingActivityGroups streamState={streamState} />
          </div>
        )}
      </div>
    </article>
  );
}

function SkillToolTimeline({
  toolCallItems,
}: {
  toolCallItems: LighthouseV2StreamToolCallActivityItem[];
}) {
  if (toolCallItems.length === 0) {
    return (
      <p className="text-text-neutral-secondary pt-1 text-xs">
        Waiting for the first tool call…
      </p>
    );
  }

  return (
    <div className="flex flex-col pt-1">
      {toolCallItems.map((toolCall) => {
        const isRunning =
          toolCall.status === LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING;
        return (
          <ChainOfThoughtStep
            key={toolCall.id}
            label={formatToolName(toolCall.name)}
            status={
              isRunning
                ? CHAIN_OF_THOUGHT_STATUS.ACTIVE
                : CHAIN_OF_THOUGHT_STATUS.COMPLETE
            }
            icon={isRunning ? Spinner : undefined}
          />
        );
      })}
    </div>
  );
}

function isToolCallItem(
  item: LighthouseV2StreamState["activityItems"][number],
): item is LighthouseV2StreamToolCallActivityItem {
  return item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TOOL_CALL;
}

function ElapsedTime({ startedAt }: { startedAt?: string }) {
  const elapsedSeconds = useElapsedSeconds(startedAt);
  if (startedAt === undefined) return null;
  const minutes = Math.floor(elapsedSeconds / 60);
  const seconds = elapsedSeconds % 60;
  return (
    <>
      {" · "}
      {String(minutes).padStart(2, "0")}:{String(seconds).padStart(2, "0")}
    </>
  );
}

// Ticking clock via useSyncExternalStore: the interval is the external store,
// and the floored second count keeps snapshots stable between ticks.
function useElapsedSeconds(startedAt?: string): number {
  return useSyncExternalStore(
    subscribeToClock,
    () => getElapsedSeconds(startedAt),
    // Stable server/hydration snapshot: a time-derived value would differ
    // between the server render and the hydration pass.
    () => 0,
  );
}

function subscribeToClock(onStoreChange: () => void): () => void {
  const intervalId = window.setInterval(onStoreChange, 1000);
  return () => window.clearInterval(intervalId);
}

function getElapsedSeconds(startedAt?: string): number {
  if (!startedAt) return 0;
  const started = new Date(startedAt).getTime();
  if (Number.isNaN(started)) return 0;
  return Math.max(0, Math.floor((Date.now() - started) / 1000));
}
