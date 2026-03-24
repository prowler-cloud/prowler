"use client";

import { format } from "date-fns";
import { CalendarIcon, ChevronDown } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { Calendar } from "@/components/shadcn/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { cn } from "@/lib/utils";

/** Batch mode: caller controls both the pending date value and the notification callback (all-or-nothing). */
interface CustomDatePickerBatchProps {
  /**
   * Called instead of updating the URL directly.
   * Receives the filter key ("inserted_at") and the formatted date string (YYYY-MM-DD).
   */
  onBatchChange: (filterKey: string, value: string) => void;
  /**
   * Controlled date value from the parent (pending state).
   * Expected format: YYYY-MM-DD (or any value parseable by `new Date()`).
   */
  value: string | undefined;
}

/** Instant mode: URL-driven — neither callback nor controlled value. */
interface CustomDatePickerInstantProps {
  onBatchChange?: never;
  value?: never;
}

type CustomDatePickerProps =
  | CustomDatePickerBatchProps
  | CustomDatePickerInstantProps;

const parseDate = (raw: string | null | undefined): Date | undefined => {
  if (!raw) return undefined;
  try {
    // Use T00:00:00 suffix to avoid timezone offset shifting the date
    return new Date(raw + "T00:00:00");
  } catch {
    return undefined;
  }
};

export const CustomDatePicker = ({
  onBatchChange,
  value: valueProp,
}: CustomDatePickerProps = {}) => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [open, setOpen] = useState(false);

  // Derive the displayed date directly from the controlled source of truth:
  // - Batch mode: `valueProp` from parent (pending state)
  // - Instant mode: `searchParams` from URL (re-renders automatically on URL change)
  const date =
    valueProp !== undefined
      ? parseDate(valueProp)
      : parseDate(searchParams.get("filter[inserted_at]"));

  const applyDateFilter = (selectedDate: Date | undefined) => {
    if (onBatchChange) {
      // Batch mode: notify caller instead of updating URL
      onBatchChange(
        "inserted_at",
        selectedDate ? format(selectedDate, "yyyy-MM-dd") : "",
      );
      return;
    }

    // Instant mode (default): push to URL immediately
    if (selectedDate) {
      // Format as YYYY-MM-DD for the API
      updateFilter("inserted_at", format(selectedDate, "yyyy-MM-dd"));
    } else {
      updateFilter("inserted_at", null);
    }
  };

  const handleDateSelect = (newDate: Date | undefined) => {
    applyDateFilter(newDate);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-haspopup="dialog"
          aria-expanded={open}
          className={cn(
            "border-border-input-primary bg-bg-input-primary text-bg-button-secondary dark:bg-input/30 dark:hover:bg-input/50 focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press flex h-[52px] w-full items-center justify-between gap-2 rounded-lg border px-4 py-3 text-sm whitespace-nowrap shadow-xs transition-[color,box-shadow] outline-none focus-visible:ring-1 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
            !date && "text-bg-button-secondary",
          )}
        >
          <span className="flex items-center gap-2">
            <CalendarIcon className="text-bg-button-secondary size-5 opacity-70" />
            {date ? format(date, "PPP") : "Pick a date"}
          </span>
          <ChevronDown
            className={cn(
              "text-bg-button-secondary size-6 shrink-0 opacity-70 transition-transform duration-200",
              open && "rotate-180",
            )}
          />
        </button>
      </PopoverTrigger>
      <PopoverContent
        className="border-border-input-primary bg-bg-input-primary w-auto p-0"
        align="start"
      >
        <Calendar mode="single" selected={date} onSelect={handleDateSelect} />
      </PopoverContent>
    </Popover>
  );
};
