"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ChevronRightIcon } from "lucide-react";
import { KeyboardEvent } from "react";

import { Checkbox } from "@/components/shadcn/checkbox";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { TreeNodeProps } from "@/types/tree";

import { TreeLeaf } from "./tree-leaf";
import { TreeSpinner } from "./tree-spinner";
import { getAllDescendantIds } from "./utils";

/**
 * TreeNode component for rendering expandable nodes with children.
 *
 * Features:
 * - Collapsible content using Radix UI
 * - Indeterminate checkbox state when partially selected
 * - Recursive selection of all descendants
 * - Loading spinner state
 * - Custom rendering via renderItem prop
 * - Keyboard navigation support (Enter/Space to select, Arrow keys to expand)
 */
export function TreeNode({
  item,
  level,
  selectedIds,
  expandedIds,
  onSelectionChange,
  onExpandedChange,
  showCheckboxes,
  renderItem,
  expandAll,
  enableSelectChildren,
}: TreeNodeProps) {
  const isExpanded = expandAll || expandedIds.includes(item.id);
  const isSelected = selectedIds.includes(item.id);

  // Calculate indeterminate state based on descendant selection
  const descendantIds = getAllDescendantIds(item);
  const selectedDescendantCount = descendantIds.filter((id) =>
    selectedIds.includes(id),
  ).length;
  const isIndeterminate =
    selectedDescendantCount > 0 &&
    selectedDescendantCount < descendantIds.length;

  const handleToggleExpand = () => {
    const newExpandedIds = isExpanded
      ? expandedIds.filter((id) => id !== item.id)
      : [...expandedIds, item.id];
    onExpandedChange(newExpandedIds);
  };

  const handleSelect = () => {
    onSelectionChange(item.id, item);
  };

  const handleContentClick = showCheckboxes ? handleSelect : handleToggleExpand;

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    switch (event.key) {
      case "Enter":
      case " ":
        event.preventDefault();
        handleContentClick();
        break;
      case "ArrowRight":
        if (!isExpanded) {
          event.preventDefault();
          handleToggleExpand();
        }
        break;
      case "ArrowLeft":
        if (isExpanded) {
          event.preventDefault();
          handleToggleExpand();
        }
        break;
    }
  };

  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-2 rounded-md px-2 py-1.5",
          "hover:bg-prowler-white/5 cursor-pointer",
          "focus-visible:ring-border-input-primary-press focus-visible:ring-2 focus-visible:outline-none",
          isSelected && "bg-prowler-white/10",
          item.disabled && "cursor-not-allowed opacity-50",
          item.className,
        )}
        style={{ paddingLeft: `${level * 1.25}rem` }}
        role="treeitem"
        tabIndex={item.disabled ? -1 : 0}
        aria-expanded={isExpanded}
        aria-selected={isSelected}
        aria-disabled={item.disabled}
        onClick={handleContentClick}
        onKeyDown={handleKeyDown}
      >
        <button
          className="hover:bg-prowler-white/10 shrink-0 rounded p-0.5"
          aria-label={isExpanded ? "Collapse" : "Expand"}
          onClick={(e) => {
            e.stopPropagation();
            handleToggleExpand();
          }}
          tabIndex={-1}
        >
          {item.isLoading ? (
            <TreeSpinner className="size-4" />
          ) : (
            <ChevronRightIcon
              className={cn(
                "h-4 w-4 transition-transform duration-200",
                isExpanded && "rotate-90",
              )}
            />
          )}
        </button>

        {showCheckboxes && (
          <Checkbox
            size="sm"
            checked={isSelected}
            indeterminate={isIndeterminate && !isSelected}
            onCheckedChange={handleSelect}
            disabled={item.disabled}
            onClick={(e: React.MouseEvent) => e.stopPropagation()}
          />
        )}

        <div className="min-w-0 flex-1">
          {renderItem ? (
            renderItem({
              item,
              level,
              isLeaf: false,
              isSelected,
              isExpanded,
              isIndeterminate,
              hasChildren: true,
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
      </div>

      <AnimatePresence initial={false}>
        {isExpanded && (
          <motion.ul
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="space-y-0.5 overflow-hidden"
            role="group"
          >
            {item.children?.map((child) => (
              <li key={child.id}>
                {child.children ? (
                  <TreeNode
                    item={child}
                    level={level + 1}
                    selectedIds={selectedIds}
                    expandedIds={expandedIds}
                    onSelectionChange={onSelectionChange}
                    onExpandedChange={onExpandedChange}
                    showCheckboxes={showCheckboxes}
                    renderItem={renderItem}
                    expandAll={expandAll}
                    enableSelectChildren={enableSelectChildren}
                  />
                ) : (
                  <TreeLeaf
                    item={child}
                    level={level + 1}
                    selectedIds={selectedIds}
                    onSelectionChange={onSelectionChange}
                    showCheckboxes={showCheckboxes}
                    renderItem={renderItem}
                  />
                )}
              </li>
            ))}
          </motion.ul>
        )}
      </AnimatePresence>
    </div>
  );
}
