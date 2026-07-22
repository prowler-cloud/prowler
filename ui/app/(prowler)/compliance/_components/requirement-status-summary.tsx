"use client";

import type { ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { ScrollArea } from "@/components/shadcn/scroll-area";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";

import type { CrossProviderStatus } from "../_types";

export interface RequirementStatusEntry {
  key: string;
  /** Short label shown in the breakdown popover. */
  label: string;
  /** Optional icon rendered before the label in the breakdown popover. */
  icon?: ReactNode;
  status: CrossProviderStatus;
}

/** Statuses in triage order — failures first, evidence last. */
const STATUS_ORDER: readonly CrossProviderStatus[] = ["FAIL", "MANUAL", "PASS"];

const SCROLLABLE_BREAKDOWN_MIN_ROWS = 13;

export const REQUIREMENT_ENTITY_LABEL = {
  ACCOUNTS: "accounts",
  PROVIDERS: "providers",
} as const;

type RequirementEntityLabel =
  (typeof REQUIREMENT_ENTITY_LABEL)[keyof typeof REQUIREMENT_ENTITY_LABEL];

/**
 * Aggregated per-status counts for a requirement row whose column axis has
 * too many members to chip inline (many accounts of one provider type, or
 * many provider types). Constant footprint regardless of N: one count badge
 * per status present, with the full per-member breakdown in an accessible
 * popover.
 */
export const RequirementStatusSummary = ({
  entries,
  entityLabel = REQUIREMENT_ENTITY_LABEL.PROVIDERS,
}: {
  entries: RequirementStatusEntry[];
  entityLabel?: RequirementEntityLabel;
}) => {
  const counts = STATUS_ORDER.map((status) => ({
    status,
    count: entries.filter((entry) => entry.status === status).length,
  })).filter(({ count }) => count > 0);

  const breakdownList = (
    <div className="flex flex-col gap-1.5">
      {entries.map((entry) => (
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
    </div>
  );

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="bare"
          size="link-xs"
          aria-label={`Show status breakdown for ${entries.length} ${entityLabel}`}
          data-testid="requirement-status-summary"
        >
          {counts.map(({ status, count }) => (
            <span key={status} className="inline-flex items-center gap-1">
              <StatusFindingBadge status={status as FindingStatus} size="sm" />
              <span className="text-text-neutral-secondary text-xs tabular-nums">
                ×{count}
              </span>
            </span>
          ))}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end">
        {entries.length >= SCROLLABLE_BREAKDOWN_MIN_ROWS ? (
          <ScrollArea size="md">{breakdownList}</ScrollArea>
        ) : (
          breakdownList
        )}
      </PopoverContent>
    </Popover>
  );
};
