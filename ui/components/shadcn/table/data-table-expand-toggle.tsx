"use client";

import { Row } from "@tanstack/react-table";
import { ChevronRightIcon } from "lucide-react";

import { cn } from "@/lib/utils";

interface DataTableExpandToggleProps<TData> {
  row: Row<TData>;
  /**
   * Explicit expanded state to ensure React Compiler re-renders when state changes.
   * TanStack Table Row instances keep stable references — getter methods like
   * `row.getIsExpanded()` read mutable state that React Compiler cannot track.
   * Pass this prop from the parent to break memoization.
   */
  isExpanded?: boolean;
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
 *   cell: ({ row }) => (
 *     <DataTableExpandToggle row={row} isExpanded={row.getIsExpanded()} />
 *   ),
 * }
 * ```
 */
export function DataTableExpandToggle<TData>({
  row,
  isExpanded: isExpandedProp,
}: DataTableExpandToggleProps<TData>) {
  const isExpanded = isExpandedProp ?? row.getIsExpanded();

  if (!row.getCanExpand()) {
    return <div className="w-4" />;
  }

  return (
    <button
      onClick={row.getToggleExpandedHandler()}
      className={cn(
        "rounded transition-colors",
        "hover:bg-prowler-white/10",
        "focus-visible:ring-border-input-primary-press focus-visible:ring-2 focus-visible:outline-none",
      )}
      aria-label={isExpanded ? "Collapse row" : "Expand row"}
      aria-expanded={isExpanded}
    >
      <ChevronRightIcon
        className={cn(
          "text-text-neutral-tertiary h-4 w-4 shrink-0 transition-transform duration-200",
          isExpanded && "rotate-90",
        )}
      />
    </button>
  );
}
