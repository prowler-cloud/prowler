"use client";

import { CalendarClock } from "lucide-react";
import { Controller, type UseFormReturn } from "react-hook-form";

import {
  Checkbox,
  Field,
  FieldError,
  FieldLabel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { formatScheduleHour } from "@/lib/schedules";
import { SCHEDULE_FREQUENCY, type ScheduleFormValues } from "@/types/schedules";

const FREQUENCY_OPTIONS = [
  { value: SCHEDULE_FREQUENCY.DAILY, label: "Daily" },
  { value: SCHEDULE_FREQUENCY.INTERVAL, label: "Every 48 hours" },
  { value: SCHEDULE_FREQUENCY.WEEKLY, label: "Weekly" },
  { value: SCHEDULE_FREQUENCY.MONTHLY, label: "Monthly" },
] as const;

const TIMEZONE_OPTIONS = [
  "UTC",
  "Europe/Madrid",
  "Europe/London",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
] as const;

const WEEKDAY_OPTIONS = [
  { value: 0, label: "Sunday" },
  { value: 1, label: "Monday" },
  { value: 2, label: "Tuesday" },
  { value: 3, label: "Wednesday" },
  { value: 4, label: "Thursday" },
  { value: 5, label: "Friday" },
  { value: 6, label: "Saturday" },
] as const;

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, hour) => ({
  value: hour,
  label: formatScheduleHour(hour),
}));

const MONTH_DAY_OPTIONS = Array.from({ length: 28 }, (_, index) => index + 1);

interface ScanScheduleFieldsProps {
  form: UseFormReturn<ScheduleFormValues>;
  disabled?: boolean;
  showLaunchInitialScan?: boolean;
}

function NumberSelect({
  label,
  value,
  values,
  onChange,
  disabled,
}: {
  label: string;
  value: number;
  values: ReadonlyArray<{ value: number; label: string }>;
  onChange: (value: number) => void;
  disabled?: boolean;
}) {
  return (
    <Field>
      <FieldLabel>{label}</FieldLabel>
      <Select
        value={String(value)}
        onValueChange={(nextValue) => onChange(Number(nextValue))}
        disabled={disabled}
      >
        <SelectTrigger aria-label={label}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {values.map((option) => (
            <SelectItem key={option.value} value={String(option.value)}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  );
}

export function ScanScheduleFields({
  form,
  disabled = false,
  showLaunchInitialScan = false,
}: ScanScheduleFieldsProps) {
  const frequency = form.watch("frequency");
  const timezone = form.watch("timezone");
  const timezoneOptions = TIMEZONE_OPTIONS.includes(
    timezone as (typeof TIMEZONE_OPTIONS)[number],
  )
    ? TIMEZONE_OPTIONS
    : ([timezone, ...TIMEZONE_OPTIONS] as const);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-2">
        <CalendarClock className="text-text-neutral-primary size-5" />
        <h3 className="text-text-neutral-primary text-sm font-medium">
          Scan Schedule
        </h3>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Controller
          control={form.control}
          name="hour"
          render={({ field }) => (
            <NumberSelect
              label="Scan Time"
              value={field.value}
              values={HOUR_OPTIONS}
              onChange={field.onChange}
              disabled={disabled}
            />
          )}
        />

        <Controller
          control={form.control}
          name="timezone"
          render={({ field }) => (
            <Field>
              <FieldLabel>Timezone</FieldLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={disabled}
              >
                <SelectTrigger aria-label="Timezone">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent width="wide">
                  {timezoneOptions.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {form.formState.errors.timezone?.message && (
                <FieldError>
                  {form.formState.errors.timezone.message}
                </FieldError>
              )}
            </Field>
          )}
        />

        <Controller
          control={form.control}
          name="frequency"
          render={({ field }) => (
            <Field>
              <FieldLabel>Repeats</FieldLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={disabled}
              >
                <SelectTrigger aria-label="Repeats">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FREQUENCY_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
        />
      </div>

      {frequency === SCHEDULE_FREQUENCY.WEEKLY && (
        <Controller
          control={form.control}
          name="dayOfWeek"
          render={({ field }) => (
            <NumberSelect
              label="Day of week"
              value={field.value}
              values={WEEKDAY_OPTIONS}
              onChange={field.onChange}
              disabled={disabled}
            />
          )}
        />
      )}

      {frequency === SCHEDULE_FREQUENCY.MONTHLY && (
        <Controller
          control={form.control}
          name="dayOfMonth"
          render={({ field }) => (
            <NumberSelect
              label="Day of month"
              value={field.value}
              values={MONTH_DAY_OPTIONS.map((day) => ({
                value: day,
                label: String(day),
              }))}
              onChange={field.onChange}
              disabled={disabled}
            />
          )}
        />
      )}

      <p className="text-text-neutral-secondary text-sm">
        The next scheduled scan will start on the selected hour in {timezone}.
      </p>

      {showLaunchInitialScan && (
        <Controller
          control={form.control}
          name="launchInitialScan"
          render={({ field }) => (
            <label className="flex items-center gap-3 text-sm font-medium">
              <Checkbox
                checked={field.value}
                onCheckedChange={(checked) => field.onChange(checked === true)}
                disabled={disabled}
                aria-label="Launch an initial scan now for immediate findings"
              />
              <span>Launch an initial scan now for immediate findings</span>
            </label>
          )}
        />
      )}
    </div>
  );
}
