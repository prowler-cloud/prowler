"use client";

import { KeyboardEvent } from "react";

import { Checkbox } from "@/components/shadcn/checkbox";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { TreeLeafProps } from "@/types/tree";

import { TreeSpinner } from "./tree-spinner";

/**
 * TreeLeaf component for rendering leaf nodes (nodes without children).
 *
 * Features:
 * - Selection via checkbox or click
 * - Loading spinner state
 * - Custom rendering via renderItem prop
 * - Indentation based on nesting level
 * - Keyboard navigation support (Enter/Space to select)
 */
export function TreeLeaf({
  item,
  level,
  selectedIds,
  onSelectionChange,
  showCheckboxes,
  renderItem,
}: TreeLeafProps) {
  const isSelected = selectedIds.includes(item.id);

  const handleSelect = () => {
    if (!item.disabled) {
      onSelectionChange(item.id, item);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      handleSelect();
    }
  };

  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md px-2 py-1.5",
        "hover:bg-prowler-white/5 cursor-pointer",
        "focus-visible:ring-border-input-primary-press focus-visible:ring-2 focus-visible:outline-none",
        isSelected && "bg-prowler-white/10",
        item.disabled && "cursor-not-allowed opacity-50",
        item.className,
      )}
      style={{ paddingLeft: `${level * 1.25 + 1.5}rem` }}
      onClick={handleSelect}
      onKeyDown={handleKeyDown}
      role="treeitem"
      tabIndex={item.disabled ? -1 : 0}
      aria-selected={isSelected}
      aria-disabled={item.disabled}
    >
      {item.isLoading && <TreeSpinner className="size-4" />}

      {showCheckboxes && (
        <Checkbox
          size="sm"
          checked={isSelected}
          onCheckedChange={handleSelect}
          disabled={item.disabled}
          onClick={(e: React.MouseEvent) => e.stopPropagation()}
        />
      )}

      {renderItem ? (
        renderItem({
          item,
          level,
          isLeaf: true,
          isSelected,
          hasChildren: false,
        })
      ) : (
        <div className="flex min-w-0 flex-1 items-center gap-2">
          {item.icon && <item.icon className="h-4 w-4 shrink-0" />}
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="truncate text-base">{item.name}</span>
            </TooltipTrigger>
            <TooltipContent side="top">{item.name}</TooltipContent>
          </Tooltip>
        </div>
      )}
    </div>
  );
}
