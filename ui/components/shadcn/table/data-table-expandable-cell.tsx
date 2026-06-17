"use client";

import { Row } from "@tanstack/react-table";
import { CornerDownRightIcon } from "lucide-react";

import { DataTableExpandToggle } from "./data-table-expand-toggle";

/**
 * Indentation per nesting level in rem units.
 * Matches the parent's icon (w-4 = 1rem) + gap-2 (0.5rem) = 1.5rem,
 * so the child's first icon aligns horizontally with the parent's checkbox.
 */
const INDENT_PER_LEVEL_REM = 1.5;

interface DataTableExpandableCellProps<TData> {
  row: Row<TData>;
  children: React.ReactNode;
  /** Whether to show the expand/collapse toggle (default: true) */
  showToggle?: boolean;
  /** Explicit expanded state — pass to break React Compiler memoization */
  isExpanded?: boolean;
  /** Hide the CornerDownRight icon even for child rows (e.g. OUs that can expand) */
  hideChildIcon?: boolean;
  /** Optional slot rendered after expand arrows and before children (e.g. checkbox) */
  checkboxSlot?: React.ReactNode;
}

/**
 * DataTableExpandableCell is a wrapper component for table cells that need
 * to display content with proper indentation for nested rows.
 *
 * Features:
 * - Automatically indents content based on row depth
 * - Shows CornerDownRight icon for child rows (depth > 0)
 * - Optionally includes the expand/collapse toggle for parent rows
 * - Maintains proper alignment for all nesting levels
 *
 * @example
 * ```tsx
 * // In column definition:
 * {
 *   accessorKey: "name",
 *   header: "Name",
 *   cell: ({ row }) => (
 *     <DataTableExpandableCell row={row}>
 *       <span>{row.original.name}</span>
 *     </DataTableExpandableCell>
 *   ),
 * }
 * ```
 */
export function DataTableExpandableCell<TData>({
  row,
  children,
  showToggle = true,
  isExpanded,
  hideChildIcon = false,
  checkboxSlot,
}: DataTableExpandableCellProps<TData>) {
  const isChildRow = row.depth > 0;
  const canExpand = row.getCanExpand();

  return (
    <div
      className="flex min-w-0 items-center gap-2 overflow-hidden"
      style={{ paddingLeft: `${row.depth * INDENT_PER_LEVEL_REM}rem` }}
    >
      {showToggle && (
        <>
          {isChildRow && !hideChildIcon && (
            <CornerDownRightIcon className="text-text-neutral-tertiary h-4 w-4 shrink-0" />
          )}
          {canExpand ? (
            <DataTableExpandToggle row={row} isExpanded={isExpanded} />
          ) : !isChildRow ? (
            <div className="w-4" />
          ) : null}
        </>
      )}
      {checkboxSlot && (
        <div className="mr-2 flex items-center">{checkboxSlot}</div>
      )}
      {children}
    </div>
  );
}
