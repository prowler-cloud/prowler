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
  base: "relative inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
  border: "border-r border-zinc-800 last:border-r-0",
  text: "text-text-neutral-quaternary hover:text-text-neutral-quaternary",
  active: "data-[state=active]:text-text-neutral-quaternary",
  underline:
    "after:absolute after:bottom-0 after:left-1/2 after:h-[2px] after:w-0 after:-translate-x-1/2 after:bg-emerald-300 after:transition-all after:duration-200 data-[state=active]:after:w-[calc(100%-2rem)]",
  focus:
    "focus-visible:ring-2 focus-visible:ring-emerald-300 focus-visible:ring-offset-2 focus-visible:ring-offset-bg-neutral-secondary focus-visible:outline-none",
} as const;

export const TimeRangeSelector = ({
  value,
  onChange,
  isLoading = false,
}: TimeRangeSelectorProps) => {
  return (
    <div
      className="inline-flex items-center gap-2 rounded-full border bg-neutral-900 p-1"
      style={{ borderColor: "var(--border-time-range)" }}
    >
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
