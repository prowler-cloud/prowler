"use client";

import { Button, ButtonGroup } from "@heroui/button";
import { DatePicker } from "@heroui/date-picker";
import {
  getLocalTimeZone,
  parseDate,
  startOfMonth,
  startOfWeek,
  today,
} from "@internationalized/date";
import { useLocale } from "@react-aria/i18n";
import type { DateValue } from "@react-types/datepicker";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomDatePicker = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();

  const [value, setValue] = useState<DateValue | null>(() => {
    const dateParam = searchParams.get("filter[inserted_at]");
    if (!dateParam) return null;
    try {
      return parseDate(dateParam);
    } catch {
      return null;
    }
  });

  const { locale } = useLocale();

  const now = today(getLocalTimeZone());
  const nextWeek = startOfWeek(now.add({ weeks: 1 }), locale);
  const nextMonth = startOfMonth(now.add({ months: 1 }));

  const applyDateFilter = (date: DateValue | null) => {
    if (date) {
      updateFilter("inserted_at", date.toString());
    } else {
      updateFilter("inserted_at", null);
    }
  };

  const initialRender = useRef(true);

  useEffect(() => {
    if (initialRender.current) {
      initialRender.current = false;
      return;
    }
    const params = new URLSearchParams(searchParams.toString());
    if (params.size === 0) {
      setValue(null);
    }
  }, [searchParams]);

  const handleDateChange = (newValue: DateValue | null) => {
    setValue(newValue);
    applyDateFilter(newValue);
  };

  return (
    <div className="flex w-full flex-col md:gap-2">
      <DatePicker
        style={{
          borderRadius: "0.5rem",
        }}
        aria-label="Select a Date"
        classNames={{
          base: "w-full [&]:!rounded-lg [&>*]:!rounded-lg",
          selectorButton: "text-bg-button-secondary shrink-0",
          input:
            "text-bg-button-secondary placeholder:text-bg-button-secondary text-sm",
          innerWrapper: "[&]:!rounded-lg",
          inputWrapper:
            "!border-border-input-primary !bg-bg-input-primary dark:!bg-input/30 dark:hover:!bg-input/50 hover:!bg-bg-neutral-secondary !border [&]:!rounded-lg !shadow-xs !transition-[color,box-shadow] focus-within:!border-border-input-primary-press focus-within:!ring-1 focus-within:!ring-border-input-primary-press focus-within:!ring-offset-1 !h-10 !px-4 !py-3 !outline-none",
          segment: "text-bg-button-secondary",
        }}
        popoverProps={{
          classNames: {
            content:
              "border-border-input-primary bg-bg-input-primary border rounded-lg",
          },
        }}
        CalendarTopContent={
          <ButtonGroup
            fullWidth
            className="bg-bg-neutral-secondary [&>button]:border-border-neutral-secondary [&>button]:text-bg-button-secondary px-3 pt-3 pb-2"
            radius="full"
            size="sm"
            variant="flat"
          >
            <Button onPress={() => handleDateChange(now)}>Today</Button>
            <Button onPress={() => handleDateChange(nextWeek)}>
              Next week
            </Button>
            <Button onPress={() => handleDateChange(nextMonth)}>
              Next month
            </Button>
          </ButtonGroup>
        }
        calendarProps={{
          focusedValue: value || undefined,
          onFocusChange: setValue,
          nextButtonProps: {
            variant: "bordered",
          },
          prevButtonProps: {
            variant: "bordered",
          },
        }}
        value={value}
        onChange={handleDateChange}
      />
    </div>
  );
};
