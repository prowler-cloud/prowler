"use client";

import { Check } from "lucide-react";

import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

export interface ApplyFiltersButtonProps {
  /** Whether there are pending changes that differ from the applied (URL) state */
  hasChanges: boolean;
  /** Number of filter keys that have pending changes */
  changeCount: number;
  /** Called when the user clicks "Apply Filters" */
  onApply: () => void;
  /** Called when the user clicks the discard (Undo) action */
  onDiscard: () => void;
  /** Optional extra class names for the outer wrapper */
  className?: string;
}

/**
 * Displays an "Apply Filters" button with an optional discard action.
 *
 * - Shows the count of pending changes when `hasChanges` is true.
 * - The apply button is disabled (and visually muted) when there are no changes.
 * - The Undo button only appears when there are pending changes.
 * - Uses Prowler's shadcn `Button` component.
 */
export const ApplyFiltersButton = ({
  hasChanges,
  changeCount,
  onApply,
  onDiscard,
  className,
}: ApplyFiltersButtonProps) => {
  const label =
    changeCount > 0 ? `Apply Filters (${changeCount})` : "Apply Filters";

  return (
    <div className={cn("flex items-center gap-1", className)}>
      <Button
        variant="default"
        size="sm"
        disabled={!hasChanges}
        onClick={onApply}
        aria-label={label}
      >
        <Check className="size-4" />
        {label}
      </Button>

      {hasChanges && (
        <Button
          variant="ghost"
          size="sm"
          onClick={onDiscard}
          aria-label="Undo pending filter changes"
        >
          Undo
        </Button>
      )}
    </div>
  );
};
