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
      <Badge
        variant="outline"
        className="gap-2 border-border-tag bg-bg-warning text-text-neutral-primary dark:border-border-tag dark:bg-bg-warning dark:text-text-neutral-primary"
      >
        <Loader2 size={14} className="animate-spin" />
        <span>In Progress ({progress}%)</span>
      </Badge>
    );
  }

  if (status === "completed") {
    return (
      <Badge
        variant="outline"
        className="gap-2 border-border-tag bg-bg-pass-secondary text-text-neutral-primary dark:border-border-tag dark:bg-bg-pass-secondary dark:text-text-neutral-primary"
      >
        <span>Completed</span>
      </Badge>
    );
  }

  return (
    <Badge variant="destructive" className="gap-2">
      <span>Failed</span>
    </Badge>
  );
};
