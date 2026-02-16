"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { ScanState } from "@/types/attack-paths";

interface ScanStatusBadgeProps {
  status: ScanState;
  progress?: number;
  graphDataReady?: boolean;
}

/**
 * Status badge for attack path scan status
 * Shows visual indicator for scan progress and data availability
 */
export const ScanStatusBadge = ({
  status,
  progress = 0,
  graphDataReady = false,
}: ScanStatusBadgeProps) => {
  const graphDot = graphDataReady && status !== "completed" && (
    <span className="inline-block size-2 rounded-full bg-green-500" />
  );

  const tooltipText = graphDataReady
    ? "Graph available"
    : status === "failed" || status === "completed"
      ? "Graph not available"
      : "Graph not available yet";

  const renderBadge = () => {
    if (status === "scheduled") {
      return (
        <Badge className="bg-bg-neutral-tertiary text-text-neutral-primary gap-2">
          {graphDot}
          <span>Scheduled</span>
        </Badge>
      );
    }

    if (status === "available") {
      return (
        <Badge className="bg-bg-neutral-tertiary text-text-neutral-primary gap-2">
          {graphDot}
          <span>Queued</span>
        </Badge>
      );
    }

    if (status === "executing") {
      return (
        <Badge className="bg-bg-warning-secondary text-text-neutral-primary gap-2">
          <Loader2
            size={14}
            className={
              graphDataReady ? "animate-spin text-green-500" : "animate-spin"
            }
          />
          <span>In Progress ({progress}%)</span>
        </Badge>
      );
    }

    if (status === "completed") {
      return (
        <Badge className="bg-bg-pass-secondary text-text-success-primary gap-2">
          <span>Completed</span>
        </Badge>
      );
    }

    return (
      <Badge className="bg-bg-fail-secondary text-text-error-primary gap-2">
        {graphDot}
        <span>Failed</span>
      </Badge>
    );
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>{renderBadge()}</TooltipTrigger>
      <TooltipContent>{tooltipText}</TooltipContent>
    </Tooltip>
  );
};
