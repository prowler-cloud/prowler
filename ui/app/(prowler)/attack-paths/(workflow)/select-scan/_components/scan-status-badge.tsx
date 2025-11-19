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
      <span className="inline-flex items-center gap-2 rounded-full border border-amber-400 bg-amber-400/20 px-2 py-0.5 text-xs font-medium text-amber-700 dark:border-amber-600 dark:bg-amber-950/40 dark:text-amber-400">
        <Loader2 size={14} className="animate-spin" />
        <span>In Progress ({progress}%)</span>
      </span>
    );
  }

  if (status === "completed") {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-green-400 bg-green-400/20 px-2 py-0.5 text-xs font-medium text-green-700 dark:border-green-600 dark:bg-green-950/40 dark:text-green-400">
        <span>Completed</span>
      </span>
    );
  }

  return (
    <Badge variant="destructive" className="gap-2">
      <span className="text-xs font-medium">Failed</span>
    </Badge>
  );
};
