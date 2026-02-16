"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
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
  const dataAvailableDot = graphDataReady && status !== "completed" && (
    <span
      className="bg-bg-pass-secondary inline-block size-2 rounded-full"
      title="Data available"
    />
  );

  if (status === "scheduled") {
    return (
      <Badge className="bg-bg-neutral-tertiary text-text-neutral-primary gap-2">
        {dataAvailableDot}
        <span>Scheduled</span>
      </Badge>
    );
  }

  if (status === "available") {
    return (
      <Badge className="bg-bg-neutral-tertiary text-text-neutral-primary gap-2">
        {dataAvailableDot}
        <span>Queued</span>
      </Badge>
    );
  }

  if (status === "executing") {
    return (
      <Badge className="bg-bg-warning-secondary text-text-neutral-primary gap-2">
        {dataAvailableDot || <Loader2 size={14} className="animate-spin" />}
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
      {dataAvailableDot}
      <span>Failed</span>
    </Badge>
  );
};
