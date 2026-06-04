import type { ProviderProps } from "./providers";

export const SCHEDULE_FREQUENCY = {
  DAILY: "DAILY",
  INTERVAL: "INTERVAL",
  WEEKLY: "WEEKLY",
  MONTHLY: "MONTHLY",
} as const;

export type ScheduleFrequency =
  (typeof SCHEDULE_FREQUENCY)[keyof typeof SCHEDULE_FREQUENCY];

export interface ScheduleAttributes {
  scan_enabled: boolean;
  scan_frequency: ScheduleFrequency;
  scan_hour: number | null;
  scan_timezone: string;
  scan_interval_hours: number | null;
  scan_day_of_week: number | null;
  scan_day_of_month: number | null;
}

export interface ScheduleRelationships {
  provider: {
    data: {
      type: "providers";
      id: string;
    };
  };
}

export interface ScheduleProps {
  type: "schedules";
  id: string;
  attributes: ScheduleAttributes;
  relationships: ScheduleRelationships;
}

export interface ScheduleApiResponse {
  data: ScheduleProps;
  included?: ProviderProps[];
}

export interface ScheduleUpdatePayload {
  scan_enabled: boolean;
  scan_frequency: ScheduleFrequency;
  scan_hour: number;
  scan_timezone: string;
  scan_interval_hours: number | null;
  scan_day_of_week: number | null;
  scan_day_of_month: number | null;
}

export interface ScheduleFormValues {
  frequency: ScheduleFrequency;
  hour: number;
  timezone: string;
  dayOfWeek: number;
  dayOfMonth: number;
  launchInitialScan: boolean;
}
