"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import type { ScanState } from "@/types/attack-paths";

interface ScanStatusBadgeProps {
  status: ScanState;
  progress?: number;
}

/**
 * Status badge for attack path scan status
 * Shows visual indicator and text for scan progress
 */
export const ScanStatusBadge = ({
  status,
  progress = 0,
}: ScanStatusBadgeProps) => {
  if (status === "scheduled") {
    return (
      <Badge className="bg-bg-neutral-tertiary text-text-neutral-primary gap-2">
        <span>Scheduled</span>
      </Badge>
    );
  }

  if (status === "executing") {
    return (
      <Badge className="bg-bg-warning-secondary text-neutral-primary gap-2">
        <Loader2 size={14} className="animate-spin" />
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
      <span>Failed</span>
    </Badge>
  );
};
