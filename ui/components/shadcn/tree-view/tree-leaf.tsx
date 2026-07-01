"use client";

import { KeyboardEvent } from "react";

import { Checkbox } from "@/components/shadcn/checkbox";
import { cn } from "@/lib/utils";
import { TreeLeafProps } from "@/types/tree";

import { TreeItemLabel } from "./tree-item-label";
import { TreeSpinner } from "./tree-spinner";
import { TreeStatusIndicator } from "./tree-status-indicator";
import { getTreeLeafPadding } from "./utils";

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
  const shouldReplaceCheckboxWithState =
    showCheckboxes && (item.isLoading || Boolean(item.status));
  const statusIcon =
    !item.isLoading && item.status ? (
      <TreeStatusIndicator
        status={item.status}
        errorMessage={item.errorMessage}
      />
    ) : null;

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
        item.disabled && "cursor-not-allowed opacity-50",
        item.className,
      )}
      style={{ paddingLeft: getTreeLeafPadding(level) }}
      onClick={handleSelect}
      onKeyDown={handleKeyDown}
      role="treeitem"
      tabIndex={item.disabled ? -1 : 0}
      aria-selected={isSelected}
      aria-disabled={item.disabled}
    >
      {!showCheckboxes && item.isLoading && <TreeSpinner />}
      {!showCheckboxes && statusIcon}

      {showCheckboxes && shouldReplaceCheckboxWithState && (
        <>
          {item.isLoading && <TreeSpinner />}
          {statusIcon}
        </>
      )}

      {showCheckboxes && !shouldReplaceCheckboxWithState && (
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
        <TreeItemLabel item={item} />
      )}
    </div>
  );
}
