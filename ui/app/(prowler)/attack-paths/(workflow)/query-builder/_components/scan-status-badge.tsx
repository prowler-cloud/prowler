"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { ScanState } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

const BADGE_CONFIG: Record<
  ScanState,
  { className: string; label: string; showGraphDot: boolean }
> = {
  [SCAN_STATES.SCHEDULED]: {
    className: "bg-bg-neutral-tertiary text-text-neutral-primary",
    label: "Scheduled",
    showGraphDot: true,
  },
  [SCAN_STATES.AVAILABLE]: {
    className: "bg-bg-neutral-tertiary text-text-neutral-primary",
    label: "Queued",
    showGraphDot: true,
  },
  [SCAN_STATES.EXECUTING]: {
    className: "bg-bg-warning-secondary text-text-neutral-primary",
    label: "In Progress",
    showGraphDot: false,
  },
  [SCAN_STATES.COMPLETED]: {
    className: "bg-bg-pass-secondary text-text-success-primary",
    label: "Completed",
    showGraphDot: false,
  },
  [SCAN_STATES.FAILED]: {
    className: "bg-bg-fail-secondary text-text-error-primary",
    label: "Failed",
    showGraphDot: true,
  },
};

interface ScanStatusBadgeProps {
  status: ScanState;
  progress?: number;
  graphDataReady?: boolean;
}

export const ScanStatusBadge = ({
  status,
  progress = 0,
  graphDataReady = false,
}: ScanStatusBadgeProps) => {
  const config = BADGE_CONFIG[status];

  const graphDot = graphDataReady && config.showGraphDot && (
    <span className="inline-block size-2 rounded-full bg-green-500" />
  );

  const tooltipText = graphDataReady
    ? "Graph available"
    : status === SCAN_STATES.FAILED || status === SCAN_STATES.COMPLETED
      ? "Graph not available"
      : "Graph not available yet";

  const icon =
    status === SCAN_STATES.EXECUTING ? (
      <Loader2
        size={14}
        className={
          graphDataReady ? "animate-spin text-green-500" : "animate-spin"
        }
      />
    ) : (
      graphDot
    );

  const label =
    status === SCAN_STATES.EXECUTING
      ? `${config.label} (${progress}%)`
      : config.label;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge className={`${config.className} gap-2`}>
          {icon}
          <span>{label}</span>
        </Badge>
      </TooltipTrigger>
      <TooltipContent>{tooltipText}</TooltipContent>
    </Tooltip>
  );
};
