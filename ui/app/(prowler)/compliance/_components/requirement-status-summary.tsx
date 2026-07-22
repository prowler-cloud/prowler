"use client";

import type { ReactNode } from "react";

import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

import type { CrossProviderStatus } from "../_types";

export interface RequirementStatusEntry {
  key: string;
  /** Short label shown in the hover breakdown list. */
  label: string;
  /** Optional icon rendered before the label in the breakdown list. */
  icon?: ReactNode;
  status: CrossProviderStatus;
}

/** Statuses in triage order — failures first, evidence last. */
const STATUS_ORDER: readonly CrossProviderStatus[] = ["FAIL", "MANUAL", "PASS"];

/** Hover breakdown stays glanceable; beyond this it points at the row's
 *  drill-down instead of becoming a scrolling list inside a tooltip. */
const MAX_BREAKDOWN_ROWS = 12;

/**
 * Aggregated per-status counts for a requirement row whose column axis has
 * too many members to chip inline (many accounts of one provider type, or
 * many provider types). Constant footprint regardless of N: one count badge
 * per status present, with the full per-member breakdown on hover.
 */
export const RequirementStatusSummary = ({
  entries,
}: {
  entries: RequirementStatusEntry[];
}) => {
  const counts = STATUS_ORDER.map((status) => ({
    status,
    count: entries.filter((entry) => entry.status === status).length,
  })).filter(({ count }) => count > 0);

  const breakdown = entries.slice(0, MAX_BREAKDOWN_ROWS);
  const hidden = entries.length - breakdown.length;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          data-testid="requirement-status-summary"
          className="flex shrink-0 items-center gap-2"
        >
          {counts.map(({ status, count }) => (
            <span key={status} className="inline-flex items-center gap-1">
              <StatusFindingBadge status={status as FindingStatus} size="sm" />
              <span className="text-text-neutral-secondary text-xs tabular-nums">
                ×{count}
              </span>
            </span>
          ))}
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <div className="flex flex-col gap-1.5">
          {breakdown.map((entry) => (
            <span
              key={entry.key}
              className="flex items-center justify-between gap-3"
            >
              <span className="flex min-w-0 items-center gap-1.5">
                {entry.icon}
                <span className="max-w-48 truncate text-xs">{entry.label}</span>
              </span>
              <StatusFindingBadge
                status={entry.status as FindingStatus}
                size="sm"
              />
            </span>
          ))}
          {hidden > 0 && (
            <span className="text-text-neutral-tertiary text-xs">
              +{hidden} more — expand the requirement for the full breakdown
            </span>
          )}
        </div>
      </TooltipContent>
    </Tooltip>
  );
};
