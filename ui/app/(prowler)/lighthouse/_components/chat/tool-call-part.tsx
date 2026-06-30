"use client";

import { Check, ChevronDown, TriangleAlert, Wrench } from "lucide-react";

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import {
  formatToolName,
  getToolCallContent,
  isToolCallError,
} from "@/app/(prowler)/lighthouse/_lib/tool-calls";
import type { LighthouseV2Part } from "@/app/(prowler)/lighthouse/_types";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import {
  QUERY_EDITOR_LANGUAGE,
  QueryCodeEditor,
} from "@/components/shared/query-code-editor";

// Groups consecutive finished tool calls under one collapsed disclosure so the
// "work" stays compact while surrounding text can render in chronological order.
export function ToolCalls({ parts }: { parts: LighthouseV2Part[] }) {
  if (parts.length === 0) {
    return null;
  }
  const label = getToolCallsLabel(parts);

  return (
    <ChainOfThought className="space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary">
        {label}
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent className="mt-2 space-y-1.5">
        {parts.map((part, index) => (
          <ToolCallPart key={part.id || `tool-${index}`} part={part} />
        ))}
      </ChainOfThoughtContent>
    </ChainOfThought>
  );
}

function getToolCallsLabel(parts: LighthouseV2Part[]): string {
  if (parts.length === 1) {
    const toolCall = getToolCallContent(parts[0].content);
    if (toolCall) {
      return `Used ${formatToolName(toolCall.toolName)}`;
    }
  }

  return `Used ${parts.length} ${parts.length === 1 ? "tool" : "tools"}`;
}

// One tool call as a light, collapsed row: status + humanized name, expanding to
// the arguments the agent sent and the result it got back.
function ToolCallPart({ part }: { part: LighthouseV2Part }) {
  const toolCall = getToolCallContent(part.content);
  if (!toolCall) {
    return null;
  }

  // `content.outcome` is authoritative; fall back to the part-level column.
  const outcome = toolCall.outcome ?? part.toolCallOutcome;
  const isError = isToolCallError(outcome);

  return (
    <Collapsible className="border-border-neutral-secondary rounded-[6px] border">
      <CollapsibleTrigger className="group flex w-full items-center gap-2 px-2.5 py-1.5 text-xs">
        {isError ? (
          <TriangleAlert className="text-text-error-primary size-3.5 shrink-0" />
        ) : (
          <Check className="text-text-success-primary size-3.5 shrink-0" />
        )}
        <Wrench className="text-text-neutral-tertiary size-3.5 shrink-0" />
        <span className="text-text-neutral-primary flex-1 truncate text-left">
          {formatToolName(toolCall.toolName)}
        </span>
        {isError && outcome && (
          <span className="text-text-error-primary truncate">{outcome}</span>
        )}
        <ChevronDown className="text-text-neutral-tertiary size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-180" />
      </CollapsibleTrigger>
      <CollapsibleContent className="space-y-2 px-2.5 pb-2.5">
        <ToolCallSection label="Arguments" value={toolCall.arguments} />
        <ToolCallSection label="Result" value={toolCall.result} />
      </CollapsibleContent>
    </Collapsible>
  );
}

function ToolCallSection({ label, value }: { label: string; value: unknown }) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  // String results (often markdown) render as plain text so real newlines show
  // instead of escaped "\n"; structured values render as highlighted JSON.
  const isText = typeof value === "string";
  const text = isText ? value : JSON.stringify(value, null, 2);
  if (!text) {
    return null;
  }

  return (
    <QueryCodeEditor
      ariaLabel={label}
      visibleLabel={label}
      language={
        isText ? QUERY_EDITOR_LANGUAGE.PLAIN_TEXT : QUERY_EDITOR_LANGUAGE.JSON
      }
      value={text}
      copyValue={text}
      editable={false}
      minHeight={0}
      showCopyButton
      showLineNumbers={false}
      onChange={() => {}}
    />
  );
}
