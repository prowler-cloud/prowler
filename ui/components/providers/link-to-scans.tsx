"use client";

import { StackedCell } from "@/components/shadcn";
import { formatLocalTimeWithZone } from "@/lib/date-utils";
import type { ScanScheduleSummary } from "@/types/scans";

interface LinkToScansProps {
  hasSchedule: boolean;
  schedule?: ScanScheduleSummary;
}

// Matches the scans table Schedule column: cadence on top, next-run local time
// underneath. Falls back to a plain label when the cadence is unknown.
export const LinkToScans = ({ hasSchedule, schedule }: LinkToScansProps) => {
  if (schedule) {
    return (
      <StackedCell
        primary={schedule.cadence ?? schedule.summary}
        secondary={formatLocalTimeWithZone(schedule.nextScanAt ?? null)}
      />
    );
  }

  return (
    <span className="text-text-neutral-secondary text-sm">
      {hasSchedule ? "Daily" : "None"}
    </span>
  );
};
