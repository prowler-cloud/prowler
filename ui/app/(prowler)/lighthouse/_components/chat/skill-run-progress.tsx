"use client";

import { Bot, ChevronDown, Loader2 } from "lucide-react";
import { useState, useSyncExternalStore } from "react";

import {
  CHAIN_OF_THOUGHT_STATUS,
  ChainOfThoughtSearchResult,
  ChainOfThoughtSearchResults,
  ChainOfThoughtStep,
  type ChainOfThoughtStatus,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import {
  LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE,
  LIGHTHOUSE_V2_TOOL_CALL_STATUS,
  type LighthouseV2StreamState,
  type LighthouseV2StreamToolCallActivityItem,
} from "@/app/(prowler)/lighthouse/_lib/event-reducer";
import { formatToolName } from "@/app/(prowler)/lighthouse/_lib/tool-calls";
import { cn } from "@/lib/utils";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { MessageMarkdown } from "./message-markdown";

interface SkillRunProgressProps {
  skill: LighthouseSkillDefinition;
  streamState: LighthouseV2StreamState;
  startedAt?: string;
}

// Streaming view of a skill run: a compact progress card (design 1i, no Stop —
// runs cannot be cancelled yet) that expands into the full step timeline with
// tool chips nested under their step (design 1h). Narration streams below.
export function SkillRunProgress({
  skill,
  streamState,
  startedAt,
}: SkillRunProgressProps) {
  // Local state needed: the user toggles between compact card and timeline.
  const [expanded, setExpanded] = useState(false);
  const totalSteps = skill.steps.length;
  const currentStep = clampStep(streamState.currentStep, totalSteps);
  const currentStepTitle = currentStep
    ? `Step ${currentStep} of ${totalSteps} · ${skill.steps[currentStep - 1]}`
    : "Preparing workflow…";
  const streamedText = streamState.activityItems
    .filter(
      (item) => item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TEXT,
    )
    .map((item) => item.text)
    .join("");
  const Icon = skill.icon;

  return (
    <article className="flex min-w-0 justify-start gap-3">
      <Bot className="text-text-neutral-tertiary mt-1 size-5" />
      <div className="flex max-w-[min(760px,85%)] min-w-0 flex-1 flex-col gap-3">
        <div
          className="rounded-lg p-px"
          style={{ background: "var(--gradient-lighthouse)" }}
        >
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
                  {expanded ? (
                    <>
                      Running skill
                      <ElapsedTime startedAt={startedAt} />
                    </>
                  ) : (
                    currentStepTitle
                  )}
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
              <SkillStepTimeline skill={skill} streamState={streamState} />
            ) : (
              <SkillProgressBar
                currentStep={currentStep}
                totalSteps={totalSteps}
              />
            )}
          </div>
        </div>
        {streamedText && (
          <div className="bg-bg-neutral-tertiary text-text-neutral-primary max-w-full min-w-0 rounded-[8px] px-4 py-3 text-sm">
            <MessageMarkdown text={streamedText} isStreaming />
          </div>
        )}
      </div>
    </article>
  );
}

function SkillProgressBar({
  currentStep,
  totalSteps,
}: {
  currentStep: number | null;
  totalSteps: number;
}) {
  // The active step counts half done so the bar visibly moves on every marker.
  const percent = currentStep
    ? Math.min(100, ((currentStep - 0.5) / totalSteps) * 100)
    : 5;

  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={totalSteps}
      aria-valuenow={currentStep ?? 0}
      className="bg-bg-neutral-tertiary h-1 overflow-hidden rounded-full"
    >
      <div
        className="h-full animate-pulse rounded-full transition-[width] duration-500"
        style={{
          width: `${percent}%`,
          background: "var(--gradient-lighthouse)",
        }}
      />
    </div>
  );
}

function SkillStepTimeline({
  skill,
  streamState,
}: {
  skill: LighthouseSkillDefinition;
  streamState: LighthouseV2StreamState;
}) {
  const currentStep = clampStep(streamState.currentStep, skill.steps.length);
  const toolCallItems = streamState.activityItems.filter(
    (item): item is LighthouseV2StreamToolCallActivityItem =>
      item.type === LIGHTHOUSE_V2_STREAM_ACTIVITY_ITEM_TYPE.TOOL_CALL,
  );

  return (
    <div className="flex flex-col pt-1">
      {skill.steps.map((step, index) => {
        const stepNumber = index + 1;
        // Tools fired before the first marker belong to the opening step.
        const stepTools = toolCallItems.filter(
          (item) => (item.step ?? 1) === stepNumber,
        );
        return (
          <ChainOfThoughtStep
            key={step}
            label={step}
            status={getStepStatus(stepNumber, currentStep)}
            icon={
              getStepStatus(stepNumber, currentStep) ===
              CHAIN_OF_THOUGHT_STATUS.ACTIVE
                ? Loader2
                : undefined
            }
          >
            {stepTools.length > 0 && (
              <ChainOfThoughtSearchResults>
                {stepTools.map((toolCall) => (
                  <ChainOfThoughtSearchResult
                    key={toolCall.id}
                    variant="lighthouse"
                  >
                    {toolCall.status ===
                      LIGHTHOUSE_V2_TOOL_CALL_STATUS.RUNNING && (
                      <Loader2 className="size-3 animate-spin" aria-hidden />
                    )}
                    {formatToolName(toolCall.name)}
                  </ChainOfThoughtSearchResult>
                ))}
              </ChainOfThoughtSearchResults>
            )}
          </ChainOfThoughtStep>
        );
      })}
    </div>
  );
}

function getStepStatus(
  stepNumber: number,
  currentStep: number | null,
): ChainOfThoughtStatus {
  if (currentStep === null || stepNumber > currentStep) {
    return CHAIN_OF_THOUGHT_STATUS.PENDING;
  }
  return stepNumber === currentStep
    ? CHAIN_OF_THOUGHT_STATUS.ACTIVE
    : CHAIN_OF_THOUGHT_STATUS.COMPLETE;
}

function clampStep(step: number | null, totalSteps: number): number | null {
  if (step === null) return null;
  return Math.min(Math.max(step, 1), totalSteps);
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
    () => getElapsedSeconds(startedAt),
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
