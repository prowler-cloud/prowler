"use client";

import { X } from "lucide-react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

export interface FilterChip {
  /** The filter parameter key, e.g. "filter[severity__in]" */
  key: string;
  /** Human-readable label, e.g. "Severity" */
  label: string;
  /** The individual value within the filter, e.g. "critical" */
  value: string;
  /** Optional display text for the value (defaults to `value`) */
  displayValue?: string;
}

export interface FilterSummaryStripProps {
  /** List of individual chips to render */
  chips: FilterChip[];
  /** Called when the user clicks the X on a chip */
  onRemove: (key: string, value: string) => void;
  /** Called when the user clicks "Clear all" */
  onClearAll: () => void;
  /** Optional extra class names for the outer wrapper */
  className?: string;
}

/**
 * Renders a horizontal strip of removable filter chips summarising
 * the current pending filter state.
 *
 * - Hidden when `chips` is empty.
 * - Each chip carries its own X button to remove that single value.
 * - A "Clear all" link removes everything at once.
 * - Reusable: no Findings-specific logic, driven entirely by props.
 */
export const FilterSummaryStrip = ({
  chips,
  onRemove,
  onClearAll,
  className,
}: FilterSummaryStripProps) => {
  if (chips.length === 0) return null;

  return (
    <div
      className={cn("flex flex-wrap items-center gap-2 py-2", className)}
      role="region"
      aria-label="Active filters"
      aria-live="polite"
    >
      {chips.map((chip) => (
        <Badge
          key={`${chip.key}-${chip.value}`}
          variant="outline"
          className="flex items-center gap-1 pr-1"
        >
          <span className="text-text-neutral-primary text-xs">
            <span className="font-medium">{chip.label}:</span>{" "}
            {chip.displayValue ?? chip.value}
          </span>
          <button
            type="button"
            aria-label={`Remove ${chip.label} filter: ${chip.displayValue ?? chip.value}`}
            onClick={() => onRemove(chip.key, chip.value)}
            className="text-text-neutral-secondary hover:text-text-neutral-primary ml-0.5 rounded-sm transition-colors focus-visible:ring-1 focus-visible:outline-none"
          >
            <X className="size-3" />
          </button>
        </Badge>
      ))}

      <button
        type="button"
        onClick={onClearAll}
        className="text-text-neutral-secondary hover:text-text-neutral-primary text-xs underline-offset-2 hover:underline focus-visible:ring-1 focus-visible:ring-offset-1 focus-visible:outline-none"
      >
        Clear all
      </button>
    </div>
  );
};
