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

export const CustomDatePicker = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();
  const [open, setOpen] = useState(false);

  // Derive date directly from URL — no local state needed (no debounce)
  const dateParam = searchParams.get("filter[inserted_at]");
  const date = (() => {
    if (!dateParam) return undefined;
    try {
      return new Date(dateParam);
    } catch {
      return undefined;
    }
  })();

  const handleDateSelect = (newDate: Date | undefined) => {
    if (newDate) {
      updateFilter("inserted_at", format(newDate, "yyyy-MM-dd"));
    } else {
      updateFilter("inserted_at", null);
    }
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
