import type { ProviderProps } from "./providers";

export const SCHEDULE_FREQUENCY = {
  DAILY: "DAILY",
  INTERVAL: "INTERVAL",
  WEEKLY: "WEEKLY",
  MONTHLY: "MONTHLY",
} as const;

export type ScheduleFrequency =
  (typeof SCHEDULE_FREQUENCY)[keyof typeof SCHEDULE_FREQUENCY];

/**
 * Scan-schedule capability modes. In Prowler OSS this is resolved purely from
 * the runtime environment (Cloud vs non-Cloud); the prowler-cloud overlay
 * computes a billing-aware capability and injects it via the `capability` prop.
 *
 * - `ADVANCED`: full scheduling through the new `/schedules/{providerId}` API
 *   (Prowler Cloud, subscribed/paid).
 * - `DAILY_LEGACY`: Prowler OSS / non-Cloud. Only the legacy `Daily` schedule
 *   (`/schedules/daily`) plus optional on-demand scans are allowed.
 * - `MANUAL_ONLY`: Prowler Cloud trial/onboarding. No schedules at all, only a
 *   manual on-demand scan subject to the account quota.
 */
export const SCAN_SCHEDULE_CAPABILITY = {
  ADVANCED: "ADVANCED",
  DAILY_LEGACY: "DAILY_LEGACY",
  MANUAL_ONLY: "MANUAL_ONLY",
} as const;

export type ScanScheduleCapability =
  (typeof SCAN_SCHEDULE_CAPABILITY)[keyof typeof SCAN_SCHEDULE_CAPABILITY];

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
  dayOfWeek: number;
  dayOfMonth: number;
  intervalHours: number;
  launchInitialScan: boolean;
}
