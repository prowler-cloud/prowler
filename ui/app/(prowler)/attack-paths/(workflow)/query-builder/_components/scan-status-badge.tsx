"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn";
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
  if (status === "executing") {
    return (
      <Badge className="bg-bg-warning-primary gap-2 text-white">
        <Loader2 size={14} className="animate-spin" />
        <span>In Progress ({progress}%)</span>
      </Badge>
    );
  }

  if (status === "completed") {
    return (
      <Badge className="bg-bg-pass-secondary text-text-pass-primary gap-2">
        <span>Completed</span>
      </Badge>
    );
  }

  return (
    <Badge className="bg-bg-fail-secondary text-text-fail-primary gap-2">
      <span>Failed</span>
    </Badge>
  );
};
