import { z } from "zod";

import {
  SCHEDULE_FREQUENCY,
  type ScheduleAttributes,
  type ScheduleFormValues,
  type ScheduleUpdatePayload,
} from "@/types/schedules";

const DEFAULT_SCHEDULE_HOUR = 0;
const DEFAULT_DAY_OF_WEEK = 1;
const DEFAULT_DAY_OF_MONTH = 1;
const INTERVAL_HOURS = 48;

export const scheduleFormSchema = z.object({
  frequency: z.enum(SCHEDULE_FREQUENCY),
  hour: z.number().int().min(0).max(23),
  timezone: z.string().min(1, "Timezone is required."),
  dayOfWeek: z.number().int().min(0).max(6),
  dayOfMonth: z.number().int().min(1).max(28),
  launchInitialScan: z.boolean(),
});

export function formatScheduleHour(hour: number): string {
  const normalizedHour = ((hour % 24) + 24) % 24;
  const period = normalizedHour >= 12 ? "pm" : "am";
  const displayHour = normalizedHour % 12 === 0 ? 12 : normalizedHour % 12;

  return `${displayHour}:00${period}`;
}

export function getBrowserTimezone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

export function getScheduleFormDefaults(): ScheduleFormValues {
  return {
    frequency: SCHEDULE_FREQUENCY.DAILY,
    hour: DEFAULT_SCHEDULE_HOUR,
    timezone: getBrowserTimezone(),
    dayOfWeek: DEFAULT_DAY_OF_WEEK,
    dayOfMonth: DEFAULT_DAY_OF_MONTH,
    launchInitialScan: false,
  };
}

export function getScheduleFormValues(
  schedule?: ScheduleAttributes | null,
): ScheduleFormValues {
  const defaults = getScheduleFormDefaults();

  if (!schedule || schedule.scan_hour === null) {
    return defaults;
  }

  return {
    frequency: schedule.scan_frequency,
    hour: schedule.scan_hour,
    timezone: schedule.scan_timezone || defaults.timezone,
    dayOfWeek: schedule.scan_day_of_week ?? defaults.dayOfWeek,
    dayOfMonth: schedule.scan_day_of_month ?? defaults.dayOfMonth,
    launchInitialScan: false,
  };
}

export function buildScheduleUpdatePayload(
  values: ScheduleFormValues,
): ScheduleUpdatePayload {
  return {
    scan_enabled: true,
    scan_frequency: values.frequency,
    scan_hour: values.hour,
    scan_timezone: values.timezone,
    scan_interval_hours:
      values.frequency === SCHEDULE_FREQUENCY.INTERVAL ? INTERVAL_HOURS : null,
    scan_day_of_week:
      values.frequency === SCHEDULE_FREQUENCY.WEEKLY ? values.dayOfWeek : null,
    scan_day_of_month:
      values.frequency === SCHEDULE_FREQUENCY.MONTHLY
        ? values.dayOfMonth
        : null,
  };
}
