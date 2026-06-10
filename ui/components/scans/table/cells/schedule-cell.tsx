"use client";

import { getScanScheduleLabel } from "@/components/scans/scans.utils";
import type { ScanProps } from "@/types";

// Two lines styled like DateWithTime: trigger label on top, cadence underneath.
// The scan's dates already live in the sibling date columns.
export function ScheduleCell({ scan }: { scan: ScanProps }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-text-neutral-primary text-sm whitespace-nowrap">
        {getScanScheduleLabel(scan.attributes.trigger)}
      </span>
      {scan.providerSchedule && (
        <span className="text-text-neutral-tertiary text-xs font-medium">
          {scan.providerSchedule.summary}
        </span>
      )}
    </div>
  );
}
