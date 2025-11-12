"use client";

import { cn } from "@/lib/utils";

const TIME_RANGE_OPTIONS = {
  ONE_DAY: "1D",
  FIVE_DAYS: "5D",
  ONE_WEEK: "1W",
  ONE_MONTH: "1M",
} as const;

export type TimeRange =
  (typeof TIME_RANGE_OPTIONS)[keyof typeof TIME_RANGE_OPTIONS];

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void | Promise<void>;
  isLoading?: boolean;
}

const BUTTON_STYLES = {
  base: "relative inline-flex items-center justify-center gap-2 px-6 py-3 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
  border: "border-r border-border-neutral-primary last:border-r-0",
  text: "text-text-neutral-secondary hover:text-text-neutral-primary",
  active: "data-[state=active]:text-text-neutral-primary",
  underline:
    "after:absolute after:bottom-1 after:left-1/2 after:h-px after:w-0 after:-translate-x-1/2 after:bg-emerald-400 after:transition-all data-[state=active]:after:w-8",
  focus:
    "focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:outline-none",
} as const;

export const TimeRangeSelector = ({
  value,
  onChange,
  isLoading = false,
}: TimeRangeSelectorProps) => {
  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary inline-flex items-center gap-2 rounded-full border">
      {Object.entries(TIME_RANGE_OPTIONS).map(([key, range]) => (
        <button
          key={key}
          onClick={() => onChange(range as TimeRange)}
          disabled={isLoading || false}
          data-state={value === range ? "active" : "inactive"}
          className={cn(
            BUTTON_STYLES.base,
            BUTTON_STYLES.border,
            BUTTON_STYLES.text,
            BUTTON_STYLES.active,
            BUTTON_STYLES.underline,
            BUTTON_STYLES.focus,
            isLoading && "cursor-not-allowed opacity-50",
          )}
        >
          {range}
        </button>
      ))}
    </div>
  );
};
