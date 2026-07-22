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
  type LighthouseContextItem,
} from "@/types/lighthouse-context";

interface LighthouseCurrentContextBadgeProps {
  context: LighthouseContextEnvelope | undefined;
}

export function LighthouseCurrentContextBadge({
  context,
}: LighthouseCurrentContextBadgeProps) {
  if (!context) return null;
  const { pageLabel, additionalCount } = getContextBadgeContent(context);

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Badge asChild variant="tag">
          <span tabIndex={0} aria-label={`${pageLabel} context`}>
            {buildContextLabel(pageLabel, additionalCount)}
          </span>
        </Badge>
      </TooltipTrigger>
      <LighthouseContextTooltip context={context} />
    </Tooltip>
  );
}

export function LighthouseContextBadge({
  context,
}: {
  context: LighthouseContextEnvelope;
}) {
  const { pageLabel, additionalCount } = getContextBadgeContent(context);

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Badge asChild variant="tag">
          <span tabIndex={0} aria-label={`Historical ${pageLabel} context`}>
            {buildContextLabel(pageLabel, additionalCount)}
          </span>
        </Badge>
      </TooltipTrigger>
      <LighthouseContextTooltip context={context} />
    </Tooltip>
  );
}

function getContextBadgeContent(context: LighthouseContextEnvelope) {
  const page = context.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE,
  );
  const pageLabel = page?.label ?? "Context";
  const additionalCount = context.items.filter(
    (item) =>
      item.source === LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED ||
      item.source === LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
  ).length;

  return { pageLabel, additionalCount };
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
  const itemDescriptions = context.items
    .map(getContextItemDescription)
    .filter((description) => description !== null);

  return (
    <TooltipContent maxWidth="md">
      <div className="space-y-1">
        {page?.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE && (
          <p>Page: {page.path}</p>
        )}
        {filters && <p>Filters: {filters}</p>}
        {itemDescriptions.map(({ id, text }) => (
          <p key={id}>{text}</p>
        ))}
      </div>
    </TooltipContent>
  );
}

interface ContextItemDescription {
  id: string;
  text: string;
}

function getContextItemDescription(
  item: LighthouseContextItem,
): ContextItemDescription | null {
  if (item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE) return null;
  if (
    item.source === LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC &&
    item.id === "summary"
  ) {
    return { id: `${item.kind}:${item.id}`, text: `Summary: ${item.label}` };
  }

  switch (item.kind) {
    case LIGHTHOUSE_CONTEXT_KIND.FINDING:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Finding: ${item.findingId}${item.checkId ? ` (${item.checkId})` : ""}`,
      };
    case LIGHTHOUSE_CONTEXT_KIND.RESOURCE:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Resource: ${item.resourceId}${item.resourceUid ? ` (${item.resourceUid})` : ""}`,
      };
    case LIGHTHOUSE_CONTEXT_KIND.COMPLIANCE:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Compliance: ${item.framework}${item.scanId ? ` (scan ${item.scanId})` : ""}`,
      };
    case LIGHTHOUSE_CONTEXT_KIND.ATTACK_PATH:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Attack Path: ${item.queryId ?? item.id}${item.scanId ? ` (scan ${item.scanId})` : ""}`,
      };
    case LIGHTHOUSE_CONTEXT_KIND.SCAN:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Scan: ${item.scanId ?? item.id}`,
      };
    case LIGHTHOUSE_CONTEXT_KIND.PROVIDER:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Provider: ${item.providerUid ?? item.providerId ?? item.id}`,
      };
    default: {
      const exhaustiveItem: never = item;
      return exhaustiveItem;
    }
  }
}

function buildContextLabel(pageLabel: string, additionalCount: number): string {
  return `@ ${pageLabel}${additionalCount > 0 ? ` +${additionalCount}` : ""}`;
}
