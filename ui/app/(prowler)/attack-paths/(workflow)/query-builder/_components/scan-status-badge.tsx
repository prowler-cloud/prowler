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
      <Badge variant="outline" className="border-amber-600 bg-amber-50 text-amber-900 dark:border-amber-400 dark:bg-amber-950 dark:text-amber-200 gap-2">
        <Loader2 size={14} className="animate-spin" />
        <span>In Progress ({progress}%)</span>
      </Badge>
    );
  }

  if (status === "completed") {
    return (
      <Badge variant="outline" className="border-green-600 bg-green-50 text-green-900 dark:border-green-400 dark:bg-green-950 dark:text-green-200 gap-2">
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
