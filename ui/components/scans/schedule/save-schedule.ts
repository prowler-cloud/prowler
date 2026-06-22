import { scanOnDemand, scheduleDaily } from "@/actions/scans";
import { updateSchedule } from "@/actions/schedules";
import { buildScheduleUpdatePayload } from "@/lib/schedules";
import type { ScheduleFormValues } from "@/types/schedules";

export const SAVE_SCHEDULE_STATUS = {
  ERROR: "error",
  SAVED: "saved",
  SAVED_AND_LAUNCHED: "saved_and_launched",
  SAVED_SCAN_FAILED: "saved_scan_failed",
} as const;

export type SaveScheduleStatus =
  (typeof SAVE_SCHEDULE_STATUS)[keyof typeof SAVE_SCHEDULE_STATUS];

export interface SaveScheduleParams {
  providerId: string;
  values: ScheduleFormValues;
  /** Save through the legacy `/schedules/daily` endpoint (OSS / non-Cloud). */
  useLegacyDaily?: boolean;
}

export interface SaveScheduleResult {
  status: SaveScheduleStatus;
  message?: string;
}

/** Saves a provider's scan schedule and optionally launches the initial scan. */
export async function saveScheduleWithInitialScan({
  providerId,
  values,
  useLegacyDaily = false,
}: SaveScheduleParams): Promise<SaveScheduleResult> {
  let scheduleResult: { error?: unknown } | null;

  if (useLegacyDaily) {
    const formData = new FormData();
    formData.set("providerId", providerId);
    scheduleResult = await scheduleDaily(formData);
  } else {
    scheduleResult = await updateSchedule(
      providerId,
      buildScheduleUpdatePayload(values),
    );
  }

  if (scheduleResult?.error) {
    return {
      status: SAVE_SCHEDULE_STATUS.ERROR,
      message: String(scheduleResult.error),
    };
  }

  if (!values.launchInitialScan) {
    return { status: SAVE_SCHEDULE_STATUS.SAVED };
  }

  const formData = new FormData();
  formData.set("providerId", providerId);
  const scanResult = await scanOnDemand(formData);

  if (scanResult?.error) {
    return {
      status: SAVE_SCHEDULE_STATUS.SAVED_SCAN_FAILED,
      message: String(scanResult.error),
    };
  }

  return { status: SAVE_SCHEDULE_STATUS.SAVED_AND_LAUNCHED };
}
