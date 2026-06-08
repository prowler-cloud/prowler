import { z } from "zod";

import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanScheduleCapability,
  SCHEDULE_FREQUENCY,
  type ScheduleAttributes,
  type ScheduleFormValues,
  type ScheduleUpdatePayload,
} from "@/types/schedules";

const DEFAULT_SCHEDULE_HOUR = 0;
const DEFAULT_DAY_OF_WEEK = 1;
const DEFAULT_DAY_OF_MONTH = 1;
// The backend (prowler-cloud) enforces SCAN_INTERVAL_HOURS_MIN = 24. 48 is well
// above that floor.
const INTERVAL_HOURS = 48;

export const scheduleFormSchema = z.object({
  frequency: z.enum(SCHEDULE_FREQUENCY),
  hour: z.number().int().min(0).max(23),
  dayOfWeek: z.number().int().min(0).max(6),
  dayOfMonth: z.number().int().min(1).max(28),
  launchInitialScan: z.boolean(),
});

/**
 * Default scan-schedule capability for the current environment.
 *
 * Pure function (no side effects) so it is trivial to unit-test. Prowler OSS has
 * no billing, so the only distinction it can make is Cloud vs non-Cloud:
 * non-Cloud → legacy daily-only, Cloud → full scheduling. The prowler-cloud
 * overlay computes its own (billing-aware) capability and passes it down via the
 * optional `capability` prop, overriding this default — no billing concept ever
 * leaks into OSS.
 */
export function getScanScheduleCapability(
  isCloud: boolean,
): ScanScheduleCapability {
  return isCloud
    ? SCAN_SCHEDULE_CAPABILITY.ADVANCED
    : SCAN_SCHEDULE_CAPABILITY.DAILY_LEGACY;
}

export function formatScheduleHour(hour: number): string {
  const normalizedHour = ((hour % 24) + 24) % 24;
  const period = normalizedHour >= 12 ? "pm" : "am";
  const displayHour = normalizedHour % 12 === 0 ? 12 : normalizedHour % 12;

  return `${displayHour}:00${period}`;
}

export function getBrowserTimezone(): string {
  if (typeof window === "undefined") {
    return "UTC";
  }

  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

export function getScheduleFormDefaults(): ScheduleFormValues {
  return {
    frequency: SCHEDULE_FREQUENCY.DAILY,
    hour: DEFAULT_SCHEDULE_HOUR,
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
    scan_timezone: getBrowserTimezone(),
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

/**
 * Whether a provider has an explicitly configured scan schedule.
 *
 * The schedule resource is backed by the Provider row itself: an unconfigured
 * provider — or one whose schedule was removed (DELETE resets the schedule to
 * defaults: `scan_hour=null`, but leaves `scan_enabled=true`) — comes back with
 * `scan_hour === null`. So `scan_hour` is the canonical "is configured" signal;
 * `scan_enabled` is NOT, because a freshly created provider already reports
 * `scan_enabled=true`.
 */
export function isScheduleConfigured(
  attributes: Pick<ScheduleAttributes, "scan_hour">,
): boolean {
  return attributes.scan_hour !== null;
}

/**
 * Computes the next time a schedule would run, as a local `Date`. Pure: `now` is
 * injected so it is deterministic to test. Computation is done in the browser's
 * local time, which matches the timezone shown next to it (`getBrowserTimezone`),
 * so no timezone-conversion library is needed. This is an estimate for display;
 * the backend is the source of truth for the actual fire time.
 */
export function getNextScheduledRun(
  values: ScheduleFormValues,
  now: Date,
): Date {
  if (values.frequency === SCHEDULE_FREQUENCY.INTERVAL) {
    return new Date(now.getTime() + INTERVAL_HOURS * 60 * 60 * 1000);
  }

  const next = new Date(now);
  next.setHours(values.hour, 0, 0, 0);

  switch (values.frequency) {
    case SCHEDULE_FREQUENCY.WEEKLY: {
      let delta = (values.dayOfWeek - next.getDay() + 7) % 7;
      if (delta === 0 && next <= now) delta = 7;
      next.setDate(next.getDate() + delta);
      return next;
    }
    case SCHEDULE_FREQUENCY.MONTHLY: {
      next.setDate(values.dayOfMonth);
      if (next <= now) {
        next.setMonth(next.getMonth() + 1, values.dayOfMonth);
      }
      return next;
    }
    default: {
      // DAILY
      if (next <= now) next.setDate(next.getDate() + 1);
      return next;
    }
  }
}
