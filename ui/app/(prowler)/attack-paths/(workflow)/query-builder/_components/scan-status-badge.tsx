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
      <Badge className="border-bg-warning-primary bg-bg-warning-primary gap-2 text-white opacity-80">
        <Loader2 size={14} className="animate-spin" />
        <span>In Progress ({progress}%)</span>
      </Badge>
    );
  }

  if (status === "completed") {
    return (
      <Badge className="border-bg-pass-primary bg-bg-pass-secondary text-bg-pass-primary gap-2">
        <span>Completed</span>
      </Badge>
    );
  }

  return (
    <Badge className="border-bg-fail-primary bg-bg-fail-secondary text-bg-fail-primary gap-2">
      <span>Failed</span>
    </Badge>
  );
};
