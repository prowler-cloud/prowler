"use client";

import {
  getLocalTimeZone,
  startOfMonth,
  startOfWeek,
  today,
} from "@internationalized/date";
import { Button, ButtonGroup, DatePicker } from "@nextui-org/react";
import { useLocale } from "@react-aria/i18n";
import { useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useRef } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomDatePicker = () => {
  const searchParams = useSearchParams();
  const { updateFilter } = useUrlFilters();

  const [value, setValue] = React.useState(() => {
    const dateParam = searchParams.get("filter[inserted_at]");
    return dateParam ? today(getLocalTimeZone()) : null;
  });

  const { locale } = useLocale();

  const now = today(getLocalTimeZone());
  const nextWeek = startOfWeek(now.add({ weeks: 1 }), locale);
  const nextMonth = startOfMonth(now.add({ months: 1 }));

  const applyDateFilter = useCallback(
    (date: any) => {
      if (date) {
        updateFilter("inserted_at", date.toString());
      } else {
        updateFilter("inserted_at", null);
      }
    },
    [updateFilter],
  );

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

  const handleDateChange = (newValue: any) => {
    setValue(newValue);
    applyDateFilter(newValue);
  };

  return (
    <div className="flex w-full flex-col md:gap-2">
      <DatePicker
        aria-label="Select a Date"
        label="Date"
        labelPlacement="inside"
        CalendarTopContent={
          <ButtonGroup
            fullWidth
            className="bg-content1 px-3 pb-2 pt-3 dark:bg-prowler-blue-400 [&>button]:border-default-200/60 [&>button]:text-default-500"
            radius="full"
            size="sm"
            variant="bordered"
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
        size="sm"
        variant="flat"
      />
    </div>
  );
};
