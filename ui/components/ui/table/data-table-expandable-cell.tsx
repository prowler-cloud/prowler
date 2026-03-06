"use client";

import { Row } from "@tanstack/react-table";
import { CornerDownRightIcon } from "lucide-react";

import { DataTableExpandToggle } from "./data-table-expand-toggle";

/** Indentation per nesting level in rem units */
const INDENT_PER_LEVEL_REM = 1.5;

interface DataTableExpandableCellProps<TData> {
  row: Row<TData>;
  children: React.ReactNode;
  /** Whether to show the expand/collapse toggle (default: true) */
  showToggle?: boolean;
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
}: DataTableExpandableCellProps<TData>) {
  const isChildRow = row.depth > 0;
  const canExpand = row.getCanExpand();

  return (
    <div
      className="flex items-center gap-2"
      style={{ paddingLeft: `${row.depth * INDENT_PER_LEVEL_REM}rem` }}
    >
      {showToggle && (
        <>
          {canExpand ? (
            <DataTableExpandToggle row={row} />
          ) : isChildRow ? (
            <CornerDownRightIcon className="h-4 w-4 shrink-0" />
          ) : (
            <div className="w-4" />
          )}
        </>
      )}
      {children}
    </div>
  );
}
