import { TreeDataItem } from "@/types/tree";

/**
 * Tree indentation constants (in rem units).
 * Used to calculate consistent padding for nested tree items.
 */
export const TREE_INDENT_REM = 1.25;
export const TREE_LEAF_EXTRA_PADDING_REM = 1.75;

/**
 * Calculates the left padding for a tree node based on its nesting level.
 */
export function getTreeNodePadding(level: number): string {
  return `${level * TREE_INDENT_REM}rem`;
}

/**
 * Calculates the left padding for a tree leaf based on its nesting level.
 * Leaves have extra padding to align with node content (accounting for expand button).
 */
export function getTreeLeafPadding(level: number): string {
  return `${level * TREE_INDENT_REM + TREE_LEAF_EXTRA_PADDING_REM}rem`;
}

/**
 * Recursively collects all descendant IDs from a tree item.
 *
 * @param item - The tree item to collect IDs from
 * @param includeParent - Whether to include the parent item's ID (default: false)
 * @returns Array of all descendant IDs (and optionally the parent ID)
 *
 * @example
 * Get only descendant IDs
 * const childIds = getAllDescendantIds(parentItem);
 *
 * Get parent + all descendant IDs
 * const allIds = getAllDescendantIds(parentItem, true);
 */
export function getAllDescendantIds(
  item: TreeDataItem,
  includeParent = false,
): string[] {
  const ids = includeParent ? [item.id] : [];
  if (item.children) {
    for (const child of item.children) {
      ids.push(child.id, ...getAllDescendantIds(child, false));
    }
  }
  return ids;
}
