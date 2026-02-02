"use client";

import { CircleCheckIcon, CircleXIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import { TREE_ITEM_STATUS, TreeItemStatus } from "@/types/tree";

interface TreeStatusIconProps {
  status: TreeItemStatus;
  className?: string;
}

/**
 * TreeStatusIcon component - displays success or error status for tree nodes.
 *
 * Features:
 * - CircleCheck icon for success (green)
 * - CircleX icon for error (red)
 * - Same size as TreeSpinner for consistent layout
 */
export function TreeStatusIcon({ status, className }: TreeStatusIconProps) {
  if (status === TREE_ITEM_STATUS.SUCCESS) {
    return (
      <CircleCheckIcon
        className={cn("size-5 shrink-0 text-text-success-primary", className)}
        aria-label="Success"
      />
    );
  }

  if (status === TREE_ITEM_STATUS.ERROR) {
    return (
      <CircleXIcon
        className={cn("size-5 shrink-0 text-text-error-primary", className)}
        aria-label="Error"
      />
    );
  }

  return null;
}
