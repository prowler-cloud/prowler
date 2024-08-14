"use client";

import {
  getLocalTimeZone,
  startOfMonth,
  startOfWeek,
  today,
} from "@internationalized/date";
import { Button, ButtonGroup, DatePicker } from "@nextui-org/react";
import { useDateFormatter, useLocale } from "@react-aria/i18n";
import React from "react";

export const CustomDatePicker = () => {
  const defaultDate = today(getLocalTimeZone());

  const [value, setValue] = React.useState(defaultDate);

  const { locale } = useLocale();
  const formatter = useDateFormatter({ dateStyle: "full" });

  const now = today(getLocalTimeZone());
  const nextWeek = startOfWeek(now.add({ weeks: 1 }), locale);
  const nextMonth = startOfMonth(now.add({ months: 1 }));

  return (
    <div className="flex flex-col gap-4 w-full">
      <DatePicker
        CalendarBottomContent={<div className="min-w-[380px]"></div>}
        CalendarTopContent={
          <ButtonGroup
            fullWidth
            className="px-3 pb-2 pt-3 bg-content1 [&>button]:text-default-500 [&>button]:border-default-200/60"
            radius="full"
            size="sm"
            variant="bordered"
          >
            <Button onPress={() => setValue(now)}>Today</Button>
            <Button onPress={() => setValue(nextWeek)}>Next week</Button>
            <Button onPress={() => setValue(nextMonth)}>Next month</Button>
          </ButtonGroup>
        }
        calendarProps={{
          focusedValue: value,
          onFocusChange: setValue,
          nextButtonProps: {
            variant: "bordered",
          },
          prevButtonProps: {
            variant: "bordered",
          },
        }}
        value={value}
        onChange={setValue}
        label="Scan date"
        size="sm"
        variant="flat"
      />
      <p className="text-default-500 text-sm">
        Selected date:{" "}
        {value ? formatter.format(value.toDate(getLocalTimeZone())) : "--"}
      </p>
    </div>
  );
};
