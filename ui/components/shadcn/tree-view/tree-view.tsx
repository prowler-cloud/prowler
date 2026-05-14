"use client";

import { useState } from "react";

import { cn } from "@/lib/utils";
import { TreeDataItem, TreeViewProps } from "@/types/tree";

import { TreeLeaf } from "./tree-leaf";
import { TreeNode } from "./tree-node";
import { getAllDescendantIds } from "./utils";

function getInitialExpandedIds(data: TreeDataItem[] | TreeDataItem): string[] {
  const items = Array.isArray(data) ? data : [data];

  const expandableIds: string[] = [];
  const stack = [...items];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;

    if (current.children && current.children.length > 0) {
      expandableIds.push(current.id);
      stack.push(...current.children);
    }
  }

  return expandableIds;
}

/**
 * TreeView component for rendering hierarchical data structures.
 *
 * Features:
 * - Recursive nested structure support
 * - Controlled or uncontrolled selection state
 * - Controlled or uncontrolled expansion state
 * - Auto-select children when parent is selected (optional)
 * - Indeterminate checkbox state for partial selection
 * - Loading states with spinners
 * - Custom rendering via renderItem prop
 *
 * @example
 * ```tsx
 * const data: TreeDataItem[] = [
 *   {
 *     id: "org-1",
 *     name: "Organization",
 *     children: [
 *       { id: "acc-1", name: "Account 1" },
 *       { id: "acc-2", name: "Account 2" },
 *     ],
 *   },
 * ];
 *
 * <TreeView
 *   data={data}
 *   showCheckboxes
 *   enableSelectChildren
 *   selectedIds={selectedAccounts}
 *   onSelectionChange={setSelectedAccounts}
 * />
 * ```
 */
export function TreeView({
  data,
  className,
  selectedIds: controlledSelectedIds,
  onSelectionChange,
  expandedIds: controlledExpandedIds,
  onExpandedChange,
  expandAll = false,
  showCheckboxes = false,
  enableSelectChildren = true,
  renderItem,
}: TreeViewProps) {
  const [internalSelectedIds, setInternalSelectedIds] = useState<string[]>([]);
  const [internalExpandedIds, setInternalExpandedIds] = useState<string[]>(
    expandAll ? getInitialExpandedIds(data) : [],
  );

  const selectedIds = controlledSelectedIds ?? internalSelectedIds;
  const expandedIds = controlledExpandedIds ?? internalExpandedIds;

  const handleSelectionChange = (itemId: string, item: TreeDataItem) => {
    const isSelected = selectedIds.includes(itemId);
    let newSelectedIds: string[];

    if (enableSelectChildren && item.children) {
      // When selecting a parent, also select/deselect all descendants
      const allItemIds = getAllDescendantIds(item, true);
      if (isSelected) {
        // Deselect this item and all descendants
        newSelectedIds = selectedIds.filter((id) => !allItemIds.includes(id));
      } else {
        // Select this item and all descendants
        newSelectedIds = Array.from(new Set([...selectedIds, ...allItemIds]));
      }
    } else {
      // Simple toggle without affecting children
      newSelectedIds = isSelected
        ? selectedIds.filter((id) => id !== itemId)
        : [...selectedIds, itemId];
    }

    if (onSelectionChange) {
      onSelectionChange(newSelectedIds);
    } else {
      setInternalSelectedIds(newSelectedIds);
    }
  };

  const handleExpandedChange = (newExpandedIds: string[]) => {
    if (onExpandedChange) {
      onExpandedChange(newExpandedIds);
    } else {
      setInternalExpandedIds(newExpandedIds);
    }
  };

  const items = Array.isArray(data) ? data : [data];

  return (
    <div
      className={cn("relative overflow-hidden p-2", className)}
      role="tree"
      aria-multiselectable={showCheckboxes}
    >
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item.id}>
            {item.children && item.children.length > 0 ? (
              <TreeNode
                item={item}
                level={0}
                selectedIds={selectedIds}
                expandedIds={expandedIds}
                onSelectionChange={handleSelectionChange}
                onExpandedChange={handleExpandedChange}
                showCheckboxes={showCheckboxes}
                renderItem={renderItem}
                enableSelectChildren={enableSelectChildren}
              />
            ) : (
              <TreeLeaf
                item={item}
                level={0}
                selectedIds={selectedIds}
                onSelectionChange={handleSelectionChange}
                showCheckboxes={showCheckboxes}
                renderItem={renderItem}
              />
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
