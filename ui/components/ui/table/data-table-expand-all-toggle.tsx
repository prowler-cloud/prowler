"use client";

import { Table } from "@tanstack/react-table";
import { Maximize2Icon, Minimize2Icon } from "lucide-react";

import { cn } from "@/lib/utils";

interface DataTableExpandAllToggleProps<TData> {
  table: Table<TData>;
}

/**
 * DataTableExpandAllToggle provides a button in the table header to expand
 * or collapse all rows at once.
 *
 * Features:
 * - Shows Maximize2 icon when rows are collapsed (click to expand all)
 * - Shows Minimize2 icon when rows are expanded (click to collapse all)
 * - Accessible with proper aria-label
 * - Only renders when the table has expandable rows
 *
 * @example
 * ```tsx
 * // In column definition header:
 * {
 *   id: "name",
 *   header: ({ table }) => (
 *     <div className="flex items-center gap-2">
 *       <DataTableExpandAllToggle table={table} />
 *       <span>Name</span>
 *     </div>
 *   ),
 *   cell: ({ row }) => (
 *     <DataTableExpandableCell row={row}>
 *       <span>{row.original.name}</span>
 *     </DataTableExpandableCell>
 *   ),
 * }
 * ```
 */
export function DataTableExpandAllToggle<TData>({
  table,
}: DataTableExpandAllToggleProps<TData>) {
  const isAllExpanded = table.getIsAllRowsExpanded();
  const canExpand = table.getCanSomeRowsExpand();

  if (!canExpand) {
    return null;
  }

  return (
    <button
      onClick={() => table.toggleAllRowsExpanded(!isAllExpanded)}
      className={cn(
        "rounded p-1 transition-colors",
        "hover:bg-prowler-white/10",
        "focus-visible:ring-border-input-primary-press focus-visible:ring-2 focus-visible:outline-none",
      )}
      aria-label={isAllExpanded ? "Collapse all rows" : "Expand all rows"}
      aria-expanded={isAllExpanded}
    >
      {isAllExpanded ? (
        <Minimize2Icon className="h-4 w-4" />
      ) : (
        <Maximize2Icon className="h-4 w-4" />
      )}
    </button>
  );
}
