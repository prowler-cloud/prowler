/**
 * Tree View Component Types
 *
 * Types for the TreeView component used to render hierarchical data structures
 * with support for selection, expansion, and custom rendering.
 */

/**
 * Status indicator for tree items after loading completes
 */
export const TREE_ITEM_STATUS = {
  SUCCESS: "success",
  ERROR: "error",
} as const;

export type TreeItemStatus =
  (typeof TREE_ITEM_STATUS)[keyof typeof TREE_ITEM_STATUS];

/**
 * Represents a single item in the tree structure.
 * Items can have nested children to create a hierarchical tree.
 */
export interface TreeDataItem {
  /** Unique identifier for the tree item */
  id: string;
  /** Display name for the item */
  name: string;
  /** Optional icon component to render alongside the name */
  icon?: React.ComponentType<{ className?: string }>;
  /** Child items (if present, this node is expandable) */
  children?: TreeDataItem[];
  /** Whether the item is disabled (cannot be selected) */
  disabled?: boolean;
  /** Whether the item is in a loading state (shows spinner) */
  isLoading?: boolean;
  /** Status indicator shown after loading (success/error) */
  status?: TreeItemStatus;
  /** Optional error detail used by status icon tooltip */
  errorMessage?: string;
  /** Additional CSS classes for the item */
  className?: string;
}

/**
 * Props for the main TreeView component
 */
export interface TreeViewProps {
  /** Tree data - can be a single root or array of roots */
  data: TreeDataItem[] | TreeDataItem;
  /** Additional CSS classes for the root container */
  className?: string;
  /** Controlled selected item IDs */
  selectedIds?: string[];
  /** Callback when selection changes */
  onSelectionChange?: (selectedIds: string[]) => void;
  /** Controlled expanded item IDs */
  expandedIds?: string[];
  /** Callback when expansion state changes */
  onExpandedChange?: (expandedIds: string[]) => void;
  /** Expand all nodes by default */
  expandAll?: boolean;
  /** Show checkboxes for selection */
  showCheckboxes?: boolean;
  /** Auto-select children when parent is selected */
  enableSelectChildren?: boolean;
  /** Custom render function for each item */
  renderItem?: (params: TreeRenderItemParams) => React.ReactNode;
}

/**
 * Parameters passed to the custom renderItem function
 */
export interface TreeRenderItemParams {
  /** The tree item being rendered */
  item: TreeDataItem;
  /** Nesting depth level (0 = root) */
  level: number;
  /** Whether this is a leaf node (no children) */
  isLeaf: boolean;
  /** Whether this item is selected */
  isSelected: boolean;
  /** Whether this item is expanded (only for non-leaf nodes) */
  isExpanded?: boolean;
  /** Whether this item has partial child selection (indeterminate state) */
  isIndeterminate?: boolean;
  /** Whether this item has children */
  hasChildren: boolean;
}

/**
 * Internal props for TreeNode component (expandable nodes)
 */
export interface TreeNodeProps {
  item: TreeDataItem;
  level: number;
  selectedIds: string[];
  expandedIds: string[];
  onSelectionChange: (id: string, item: TreeDataItem) => void;
  onExpandedChange: (ids: string[]) => void;
  showCheckboxes: boolean;
  renderItem?: (params: TreeRenderItemParams) => React.ReactNode;
  enableSelectChildren: boolean;
}

/**
 * Internal props for TreeLeaf component (non-expandable nodes)
 */
export interface TreeLeafProps {
  item: TreeDataItem;
  level: number;
  selectedIds: string[];
  onSelectionChange: (id: string, item: TreeDataItem) => void;
  showCheckboxes: boolean;
  renderItem?: (params: TreeRenderItemParams) => React.ReactNode;
}
