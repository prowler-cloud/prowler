"use client";

import { getScanScheduleLabel } from "@/components/scans/scans.utils";
import { StackedCell } from "@/components/shadcn";
import { formatLocalTimeWithZone } from "@/lib/date-utils";
import type { ScanProps } from "@/types";

// Trigger label on top, cadence (in the browser's timezone) underneath.
export function ScheduleCell({ scan }: { scan: ScanProps }) {
  const schedule = scan.providerSchedule;
  const localTime = formatLocalTimeWithZone(schedule?.nextScanAt ?? null);

  return (
    <StackedCell
      primary={getScanScheduleLabel(scan.attributes.trigger)}
      secondary={
        schedule
          ? `${schedule.cadence ?? schedule.summary}${localTime ? ` @ ${localTime}` : ""}`
          : undefined
      }
    />
  );
}
