"use client";

import { StackedCell } from "@/components/shadcn";
import { formatLocalTimeWithZone } from "@/lib/date-utils";
import type { ScanScheduleSummary } from "@/types/scans";

interface LinkToScansProps {
  schedule?: ScanScheduleSummary;
}

// Matches the scans table Schedule column: cadence on top, next-run local time
// underneath. Falls back to None when no configured schedule is present.
export const LinkToScans = ({ schedule }: LinkToScansProps) => {
  if (schedule) {
    return (
      <StackedCell
        primary={schedule.cadence ?? schedule.summary}
        secondary={formatLocalTimeWithZone(schedule.nextScanAt ?? null)}
      />
    );
  }

  return <span className="text-text-neutral-secondary text-sm">None</span>;
};
