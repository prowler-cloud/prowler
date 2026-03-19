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

  // In instant mode, we need local state to track the selected date so the
  // calendar stays in sync when URL params change externally (e.g. Clear Filters).
  // In batch mode, `valueProp` is the source of truth — derive date directly.
  const [localDate, setLocalDate] = useState<Date | undefined>(() =>
    parseDate(searchParams.get("filter[inserted_at]")),
  );

  // In batch mode: derive the displayed date from the controlled prop.
  // In instant mode: keep local state in sync with URL changes.
  useEffect(() => {
    if (valueProp === undefined) {
      // Instant mode: sync from URL (e.g., when Clear Filters is clicked)
      setLocalDate(parseDate(searchParams.get("filter[inserted_at]")));
    }
    // Batch mode: date is derived from valueProp directly — no state update needed
  }, [valueProp, searchParams]);

  // In batch mode, derive date from controlled prop directly to avoid stale state
  const date = valueProp !== undefined ? parseDate(valueProp) : localDate;

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
    if (valueProp === undefined) {
      // Instant mode: update local state
      setLocalDate(newDate);
    }
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
