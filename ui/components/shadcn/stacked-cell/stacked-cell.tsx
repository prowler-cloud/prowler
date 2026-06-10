import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface StackedCellProps {
  primary: ReactNode;
  secondary?: ReactNode;
  className?: string;
}

/**
 * Presentational shell for two-line table cells (the DateWithTime look):
 * primary line on top, muted secondary line underneath. Content/formatting
 * belongs to the caller.
 */
export function StackedCell({
  primary,
  secondary,
  className,
}: StackedCellProps) {
  return (
    <div
      data-slot="stacked-cell"
      className={cn("flex flex-col gap-1", className)}
    >
      <span className="text-text-neutral-primary text-sm whitespace-nowrap">
        {primary}
      </span>
      {secondary ? (
        <span className="text-text-neutral-tertiary text-xs font-medium">
          {secondary}
        </span>
      ) : null}
    </div>
  );
}
