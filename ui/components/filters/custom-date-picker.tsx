"use client";

import { format } from "date-fns";
import { CalendarIcon, ChevronDown } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { Calendar } from "@/components/shadcn/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { cn } from "@/lib/utils";

interface CustomDatePickerProps {
  /**
   * Called in batch mode instead of updating the URL directly.
   * Receives the filter key and the formatted date string (YYYY-MM-DD).
   * When provided, the component does NOT call `updateFilter`.
   */
  onBatchChange?: (filterKey: string, value: string) => void;
  /**
   * Controlled value override for batch mode.
   * When provided, this value is used as the displayed date instead of reading from URL params.
   * Expected format: YYYY-MM-DD (or any value parseable by `new Date()`).
   */
  value?: string;
}

export const CustomDatePicker = ({
  onBatchChange,
  value: valueProp,
}: CustomDatePickerProps = {}) => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [open, setOpen] = useState(false);

  // When a controlled `value` prop is provided (batch mode), use it; otherwise fall back to URL.
  const [date, setDate] = useState<Date | undefined>(() => {
    const rawValue = valueProp ?? searchParams.get("filter[inserted_at]");
    if (!rawValue) return undefined;
    try {
      return new Date(rawValue);
    } catch {
      return undefined;
    }
  });

  const applyDateFilter = (selectedDate: Date | undefined) => {
    if (onBatchChange) {
      // Batch mode: notify caller instead of updating URL
      if (selectedDate) {
        onBatchChange("inserted_at", format(selectedDate, "yyyy-MM-dd"));
      } else {
        onBatchChange("inserted_at", "");
      }
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

  // Sync local state when the controlled `value` prop changes (batch mode)
  useEffect(() => {
    if (valueProp !== undefined) {
      if (!valueProp) {
        setDate(undefined);
      } else {
        try {
          setDate(new Date(valueProp));
        } catch {
          setDate(undefined);
        }
      }
      return;
    }

    // Instant mode: sync from URL params (e.g., when Clear Filters is clicked)
    const dateParam = searchParams.get("filter[inserted_at]");
    if (!dateParam) {
      setDate(undefined);
    } else {
      try {
        setDate(new Date(dateParam));
      } catch {
        setDate(undefined);
      }
    }
  }, [valueProp, searchParams]);

  const handleDateSelect = (newDate: Date | undefined) => {
    setDate(newDate);
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
