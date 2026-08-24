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

interface LighthouseContextBadgeProps {
  context: LighthouseContextEnvelope;
}

interface ContextBadgeProps extends LighthouseContextBadgeProps {
  ariaLabelPrefix: string;
}

export function LighthouseCurrentContextBadge({
  context,
}: LighthouseCurrentContextBadgeProps) {
  if (!context) return null;
  return <ContextBadge context={context} ariaLabelPrefix="" />;
}

export function LighthouseContextBadge({
  context,
}: LighthouseContextBadgeProps) {
  return <ContextBadge context={context} ariaLabelPrefix="Historical " />;
}

function ContextBadge({ context, ariaLabelPrefix }: ContextBadgeProps) {
  const badgeContent = getContextBadgeContent(context);

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Badge asChild variant="tag">
          <span
            tabIndex={0}
            aria-label={`${ariaLabelPrefix}${badgeContent.pageLabel} context`}
          >
            {buildContextLabel(badgeContent)}
          </span>
        </Badge>
      </TooltipTrigger>
      <LighthouseContextTooltip context={context} />
    </Tooltip>
  );
}

interface ContextBadgeContent {
  pageLabel: string;
  hasFocusedDetail: boolean;
  selectionCount: number;
}

function getContextBadgeContent(
  context: LighthouseContextEnvelope,
): ContextBadgeContent {
  const page = context.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE,
  );
  const pageLabel = page?.label ?? "Context";
  const hasFocusedDetail = context.items.some(
    (item) => item.source === LIGHTHOUSE_CONTEXT_SOURCE.FOCUSED,
  );
  const selectionCount = context.items.filter(
    (item) => item.source === LIGHTHOUSE_CONTEXT_SOURCE.SELECTION,
  ).length;

  return { pageLabel, hasFocusedDetail, selectionCount };
}

function LighthouseContextTooltip({ context }: LighthouseContextBadgeProps) {
  const page = context.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE,
  );
  // Entries with no values (possible in stored envelopes) carry nothing, so
  // they count neither for the filters line nor against the page-only notice.
  const filterEntries =
    page?.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE
      ? Object.entries(page.filters ?? {}).filter(
          ([, values]) => values.length > 0,
        )
      : [];
  const filters = filterEntries
    .map(([key, values]) => `${key}: ${values.join(", ")}`)
    .join("; ");
  const itemDescriptions = context.items
    .map(getContextItemDescription)
    .filter((description) => description !== null);
  // A single filterless page item means the model only learns which page the
  // user is on — say so instead of implying richer context travels with it.
  const sharesOnlyPage =
    page?.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE &&
    context.items.length === 1 &&
    filterEntries.length === 0;

  return (
    <TooltipContent maxWidth="md">
      <div className="space-y-1">
        {page?.kind === LIGHTHOUSE_CONTEXT_KIND.PAGE && (
          <p>
            <strong>{page.label}</strong>
          </p>
        )}
        {filters && <p>Filters: {filters}</p>}
        {sharesOnlyPage && <p>Only the current page name is shared.</p>}
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
  // Automatic items are the page's own ambient snapshot (a bit of everything
  // on Overview); they travel to the agent but only user-chosen focused and
  // selection items are worth enumerating in the tooltip.
  if (item.source === LIGHTHOUSE_CONTEXT_SOURCE.AUTOMATIC) return null;

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
    case LIGHTHOUSE_CONTEXT_KIND.ALERT:
      return {
        id: `${item.kind}:${item.id}`,
        text: `Alert rule: ${item.label}`,
      };
    default: {
      const exhaustiveItem: never = item;
      return exhaustiveItem;
    }
  }
}

function buildContextLabel({
  pageLabel,
  hasFocusedDetail,
  selectionCount,
}: ContextBadgeContent): string {
  const detailLabel = hasFocusedDetail ? " · Detail" : "";
  const selectionLabel = selectionCount > 0 ? ` +${selectionCount}` : "";
  return `@ ${pageLabel}${detailLabel}${selectionLabel}`;
}
