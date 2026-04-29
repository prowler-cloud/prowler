"use client";

import { X } from "lucide-react";

import {
  Badge,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { cn } from "@/lib/utils";

export interface FilterChip {
  /** The filter parameter key, e.g. "filter[severity__in]" */
  key: string;
  /** Human-readable label, e.g. "Severity" */
  label: string;
  /** The individual value within the filter, e.g. "critical" */
  value: string;
  /** Optional complete value list when the chip groups several selections */
  values?: string[];
  /** Optional display text for the value (defaults to `value`) */
  displayValue?: string;
  /** Optional complete display value list for tooltip content */
  displayValues?: string[];
}

export interface FilterSummaryStripProps {
  /** List of individual chips to render */
  chips: FilterChip[];
  /** Called when the user clicks the X on a chip */
  onRemove?: (key: string, value?: string) => void;
  /** Optional content rendered after the last chip in the same wrapping row */
  trailingContent?: React.ReactNode;
  /** Optional extra class names for the outer wrapper */
  className?: string;
}

/**
 * Renders a horizontal strip of removable filter chips summarising
 * the current pending filter state.
 *
 * - Hidden when `chips` is empty.
 * - Each chip carries its own X button to remove that single value.
 * - Reusable: no Findings-specific logic, driven entirely by props.
 */
export const FilterSummaryStrip = ({
  chips,
  onRemove,
  trailingContent,
  className,
}: FilterSummaryStripProps) => {
  if (chips.length === 0 && !trailingContent) return null;

  return (
    <div
      className={cn("flex flex-wrap items-center gap-2", className)}
      role="region"
      aria-label="Active filters"
      aria-live="polite"
    >
      {chips.map((chip) => {
        const displayValue = chip.displayValue ?? chip.value;
        const displayValues = chip.displayValues ?? [displayValue];
        const fullLabel = `${chip.label}: ${displayValues.join(", ")}`;
        const removeValue =
          chip.values && chip.values.length > 1 ? undefined : chip.value;

        return (
          <Tooltip key={`${chip.key}-${chip.values?.join("|") ?? chip.value}`}>
            <Badge
              variant="tag"
              className="flex max-w-[280px] min-w-0 items-center gap-1 overflow-hidden pr-1"
            >
              <TooltipTrigger asChild>
                <span className="text-text-neutral-primary min-w-0 flex-1 truncate text-xs">
                  <span className="font-medium">{chip.label}:</span>{" "}
                  {displayValue}
                </span>
              </TooltipTrigger>
              {onRemove ? (
                <button
                  type="button"
                  aria-label={`Remove ${chip.label} filter: ${displayValue}`}
                  onClick={() => onRemove(chip.key, removeValue)}
                  className="text-text-neutral-secondary hover:text-text-neutral-primary ml-0.5 shrink-0 rounded-sm transition-colors focus-visible:ring-1 focus-visible:outline-none"
                >
                  <X className="size-3" />
                </button>
              ) : null}
            </Badge>
            <TooltipContent side="top">{fullLabel}</TooltipContent>
          </Tooltip>
        );
      })}
      {trailingContent}
    </div>
  );
};
