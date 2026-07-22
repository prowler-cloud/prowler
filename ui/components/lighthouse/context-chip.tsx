"use client";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  LIGHTHOUSE_CONTEXT_KIND,
  LIGHTHOUSE_CONTEXT_SOURCE,
  type LighthouseContextEnvelope,
} from "@/types/lighthouse-context";

interface LighthouseContextControlProps {
  context: LighthouseContextEnvelope | undefined;
  pageLabel: string;
  enabled: boolean;
  selectionCount: number;
  onDisable: () => void;
  onEnable: () => void;
}

export function LighthouseContextControl({
  context,
  pageLabel,
  enabled,
  selectionCount,
  onDisable,
  onEnable,
}: LighthouseContextControlProps) {
  if (!context) return null;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Badge asChild variant={enabled ? "tag" : "outline"}>
          <button
            type="button"
            aria-label={`${enabled ? "Disable" : "Enable"} ${pageLabel} context`}
            aria-pressed={enabled}
            onClick={enabled ? onDisable : onEnable}
          >
            {buildContextLabel(pageLabel, selectionCount)}
          </button>
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        {enabled
          ? `Click to stop including ${pageLabel} context in new messages.`
          : `Click to include ${pageLabel} context in new messages.`}
      </TooltipContent>
    </Tooltip>
  );
}

export function LighthouseContextBadge({
  context,
}: {
  context: LighthouseContextEnvelope;
}) {
  const page = context.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE,
  );
  const pageLabel = page?.label ?? "Context";
  const selectionCount = context.items.filter(
    (item) => item.source === LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
  ).length;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Badge asChild variant="tag">
          <span tabIndex={0} aria-label={`Historical ${pageLabel} context`}>
            {buildContextLabel(pageLabel, selectionCount)}
          </span>
        </Badge>
      </TooltipTrigger>
      <LighthouseContextTooltip context={context} />
    </Tooltip>
  );
}

function LighthouseContextTooltip({
  context,
}: {
  context: LighthouseContextEnvelope;
}) {
  const page = context.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE,
  );
  const filters =
    page?.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE
      ? Object.entries(page.filters ?? {})
          .map(([key, values]) => `${key}: ${values.join(", ")}`)
          .join("; ")
      : "";
  const summaries = context.items
    .filter(
      (item) =>
        item.kind !== LIGHTHOUSE_CONTEXT_KIND.PAGE &&
        item.source === LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC,
    )
    .map((item) => item.label)
    .join(", ");
  const types = Array.from(
    new Set(context.items.map((item) => item.kind)),
  ).join(", ");

  return (
    <TooltipContent maxWidth="md">
      <div className="space-y-1">
        {filters && <p>Filters: {filters}</p>}
        {summaries && <p>Summaries: {summaries}</p>}
        <p>Included types: {types}</p>
      </div>
    </TooltipContent>
  );
}

function buildContextLabel(pageLabel: string, selectionCount: number): string {
  return `@ ${pageLabel}${selectionCount > 0 ? ` +${selectionCount}` : ""}`;
}
