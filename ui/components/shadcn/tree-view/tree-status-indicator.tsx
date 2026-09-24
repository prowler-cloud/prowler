"use client";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { TREE_ITEM_STATUS, TreeItemStatus } from "@/types/tree";

import { TreeStatusIcon } from "./tree-status-icon";

interface TreeStatusIndicatorProps {
  status?: TreeItemStatus;
  errorMessage?: string;
}

export function TreeStatusIndicator({
  status,
  errorMessage,
}: TreeStatusIndicatorProps) {
  if (!status) {
    return null;
  }

  if (
    (status === TREE_ITEM_STATUS.ERROR ||
      status === TREE_ITEM_STATUS.PENDING) &&
    errorMessage
  ) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span>
            <TreeStatusIcon status={status} />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          <p className="text-xs">{errorMessage}</p>
        </TooltipContent>
      </Tooltip>
    );
  }

  return <TreeStatusIcon status={status} />;
}
