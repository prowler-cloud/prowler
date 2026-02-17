"use client";

import { Row } from "@tanstack/react-table";
import { ChevronRightIcon } from "lucide-react";

import { cn } from "@/lib/utils";

interface DataTableExpandToggleProps<TData> {
  row: Row<TData>;
}

/**
 * DataTableExpandToggle provides a clickable chevron button for expanding/collapsing
 * table rows that have sub-rows.
 *
 * Features:
 * - Only shows for rows that can expand (have sub-rows)
 * - Provides consistent spacing for rows without sub-rows
 * - Animates chevron rotation on expand/collapse
 * - Accessible with proper aria-label
 *
 * @example
 * ```tsx
 * // In column definition:
 * {
 *   id: "expand",
 *   cell: ({ row }) => <DataTableExpandToggle row={row} />,
 * }
 * ```
 */
export function DataTableExpandToggle<TData>({
  row,
}: DataTableExpandToggleProps<TData>) {
  if (!row.getCanExpand()) {
    // Return a spacer div for alignment when row has no sub-rows
    return <div className="w-4" />;
  }

  return (
    <button
      onClick={row.getToggleExpandedHandler()}
      className={cn(
        "rounded p-1 transition-colors",
        "hover:bg-prowler-white/10",
        "focus-visible:ring-border-input-primary-press focus-visible:ring-2 focus-visible:outline-none",
      )}
      aria-label={row.getIsExpanded() ? "Collapse row" : "Expand row"}
      aria-expanded={row.getIsExpanded()}
    >
      <ChevronRightIcon
        className={cn(
          "h-4 w-4 shrink-0 transition-transform duration-200",
          row.getIsExpanded() && "rotate-90",
        )}
      />
    </button>
  );
}
