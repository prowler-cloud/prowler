"use client";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { TreeDataItem } from "@/types/tree";

interface TreeItemLabelProps {
  /** The tree item to display */
  item: TreeDataItem;
  /** Optional text size class (defaults to text-base) */
  textClassName?: string;
}

/**
 * TreeItemLabel component - displays an item's icon and name with truncation.
 *
 * Features:
 * - Optional icon rendering
 * - Text truncation with tooltip on hover
 * - Consistent layout across tree nodes and leaves
 *
 * This component extracts the common pattern used in TreeNode and TreeLeaf
 * for displaying item content with overflow handling.
 */
export function TreeItemLabel({ item, textClassName }: TreeItemLabelProps) {
  return (
    <div className="flex min-w-0 flex-1 items-center gap-2">
      {item.icon && <item.icon className="h-4 w-4 shrink-0" />}
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={textClassName ?? "truncate text-base"}>
            {item.name}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top">{item.name}</TooltipContent>
      </Tooltip>
    </div>
  );
}
