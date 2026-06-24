"use client";

import { format } from "date-fns";
import { CalendarClock } from "lucide-react";
import type { ReactNode } from "react";
import { Controller, type UseFormReturn, useWatch } from "react-hook-form";

import {
  Checkbox,
  Field,
  FieldLabel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import {
  formatDayOfMonth,
  formatScheduleHour,
  getBrowserTimezone,
  getNextScheduledRun,
} from "@/lib/schedules";
import {
  SCHEDULE_FREQUENCY,
  SCHEDULE_WEEKDAY_LABELS,
  type ScheduleFormValues,
} from "@/types/schedules";

// The INTERVAL label is resolved at render time from the form's intervalHours.
const FREQUENCY_OPTIONS = [
  { value: SCHEDULE_FREQUENCY.DAILY, label: "Daily" },
  { value: SCHEDULE_FREQUENCY.INTERVAL, label: null },
  { value: SCHEDULE_FREQUENCY.WEEKLY, label: "Weekly" },
  { value: SCHEDULE_FREQUENCY.MONTHLY, label: "Monthly" },
] as const;

const WEEKDAY_OPTIONS = SCHEDULE_WEEKDAY_LABELS.map((label, value) => ({
  value,
  label,
}));

const HOUR_OPTIONS = Array.from({ length: 24 }, (_, hour) => ({
  value: hour,
  label: formatScheduleHour(hour),
}));

const MONTH_DAY_OPTIONS = Array.from({ length: 28 }, (_, index) => index + 1);

interface ScanScheduleFieldsProps {
  form: UseFormReturn<ScheduleFormValues>;
  disabled?: boolean;
  showLaunchInitialScan?: boolean;
  showNextScheduledCopy?: boolean;
  /** Rendered at the right of the "Scan Schedule" header row. */
  headerAction?: ReactNode;
  /**
   * When false, the frequency is locked to `Daily` and the advanced cadences
   * (interval/weekly/monthly) are disabled. Used for non-Cloud (OSS) accounts.
   */
  canUseAdvancedSchedule?: boolean;
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

function getScheduleSummary({
  frequency,
  intervalHours,
  dayOfWeek,
  dayOfMonth,
}: Pick<
  ScheduleFormValues,
  "frequency" | "intervalHours" | "dayOfWeek" | "dayOfMonth"
>) {
  switch (frequency) {
    case SCHEDULE_FREQUENCY.INTERVAL:
      return `Every ${intervalHours} hours`;
    case SCHEDULE_FREQUENCY.WEEKLY:
      return `Weekly on ${SCHEDULE_WEEKDAY_LABELS[dayOfWeek] ?? SCHEDULE_WEEKDAY_LABELS[0]}`;
    case SCHEDULE_FREQUENCY.MONTHLY:
      return `Monthly on the ${formatDayOfMonth(dayOfMonth)}`;
    default:
      return "Daily";
  }
}

export function ScanScheduleFields({
  form,
  disabled = false,
  showLaunchInitialScan = false,
  showNextScheduledCopy = false,
  headerAction,
  canUseAdvancedSchedule = true,
}: ScanScheduleFieldsProps) {
  // useWatch, not form.watch: form.watch re-renders are dropped by React Compiler memoization.
  const control = form.control;
  const [frequency, hour, dayOfWeek, dayOfMonth, intervalHours] = useWatch({
    control,
    name: ["frequency", "hour", "dayOfWeek", "dayOfMonth", "intervalHours"],
  });
  const timezone = getBrowserTimezone();
  const scheduleSummary = getScheduleSummary({
    frequency,
    intervalHours,
    dayOfWeek,
    dayOfMonth,
  });
  const frequencyLabel = (option: (typeof FREQUENCY_OPTIONS)[number]) =>
    option.label ?? `Every ${intervalHours} hours`;
  // In OSS (non-Cloud) `/schedules/daily` ignores advanced cadence/time fields,
  // so daily-only mode intentionally hides those controls instead of disabling them.
  const advancedDisabled = disabled;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <CalendarClock className="text-text-neutral-primary size-5" />
          <h3 className="text-text-neutral-primary text-sm font-medium">
            Scan Schedule
          </h3>
        </div>
        {headerAction}
      </div>

      {canUseAdvancedSchedule && (
        <>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Controller
              control={form.control}
              name="hour"
              render={({ field }) => (
                <NumberSelect
                  label="Scan Time"
                  value={field.value}
                  values={HOUR_OPTIONS}
                  onChange={field.onChange}
                  disabled={advancedDisabled}
                />
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
                    disabled={advancedDisabled}
                  >
                    <SelectTrigger aria-label="Repeats">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FREQUENCY_OPTIONS.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {frequencyLabel(option)}
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
        </>
      )}

      {showNextScheduledCopy &&
        (canUseAdvancedSchedule ? (
          <p className="text-text-neutral-secondary text-sm">
            {scheduleSummary}. The next scheduled scan will start on:{" "}
            {format(
              getNextScheduledRun(
                {
                  frequency,
                  hour,
                  dayOfWeek,
                  dayOfMonth,
                  intervalHours,
                  launchInitialScan: false,
                },
                new Date(),
              ),
              "MMM d, yyyy",
            )}{" "}
            @ {formatScheduleHour(hour)} {timezone}
          </p>
        ) : (
          <p className="text-text-neutral-secondary text-sm">
            Daily scan will run automatically.
          </p>
        ))}

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
