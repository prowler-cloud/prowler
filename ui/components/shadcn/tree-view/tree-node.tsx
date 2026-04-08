"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ChevronRightIcon } from "lucide-react";
import { KeyboardEvent } from "react";

import { Checkbox } from "@/components/shadcn/checkbox";
import { cn } from "@/lib/utils";
import { TreeNodeProps } from "@/types/tree";

import { TreeItemLabel } from "./tree-item-label";
import { TreeLeaf } from "./tree-leaf";
import { TreeSpinner } from "./tree-spinner";
import { TreeStatusIndicator } from "./tree-status-indicator";
import { getAllDescendantIds, getTreeNodePadding } from "./utils";

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
  enableSelectChildren,
}: TreeNodeProps) {
  const isExpanded = expandedIds.includes(item.id);
  const isSelected = selectedIds.includes(item.id);
  const statusIcon =
    !item.isLoading && item.status ? (
      <TreeStatusIndicator
        status={item.status}
        errorMessage={item.errorMessage}
      />
    ) : null;

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
          item.disabled && "cursor-not-allowed opacity-50",
          item.className,
        )}
        style={{ paddingLeft: getTreeNodePadding(level) }}
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
            <TreeSpinner />
          ) : (
            <ChevronRightIcon
              className={cn(
                "h-4 w-4 transition-transform duration-200",
                isExpanded && "rotate-90",
              )}
            />
          )}
        </button>

        {statusIcon}

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
            <TreeItemLabel item={item} />
          )}
        </div>
      </div>

      <AnimatePresence initial={false} mode="sync">
        {isExpanded && (
          <motion.ul
            key={`children-${item.id}`}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="mt-1 space-y-1 overflow-hidden"
            role="group"
          >
            {item.children?.map((child) => (
              <li key={child.id}>
                {child.children && child.children.length > 0 ? (
                  <TreeNode
                    item={child}
                    level={level + 1}
                    selectedIds={selectedIds}
                    expandedIds={expandedIds}
                    onSelectionChange={onSelectionChange}
                    onExpandedChange={onExpandedChange}
                    showCheckboxes={showCheckboxes}
                    renderItem={renderItem}
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
