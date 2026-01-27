import { TreeDataItem } from "@/types/tree";

/**
 * Recursively collects all descendant IDs from a tree item.
 *
 * @param item - The tree item to collect IDs from
 * @param includeParent - Whether to include the parent item's ID (default: false)
 * @returns Array of all descendant IDs (and optionally the parent ID)
 *
 * @example
 * // Get only descendant IDs
 * const childIds = getAllDescendantIds(parentItem);
 *
 * // Get parent + all descendant IDs
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
