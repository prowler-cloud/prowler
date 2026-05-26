"use client";

import { getScanScheduleLabel } from "@/components/scans/scans-table.utils";
import { DateWithTime } from "@/components/ui/entities";
import type { ScanProps } from "@/types";

export function ScheduleCell({ scan }: { scan: ScanProps }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-text-neutral-primary text-sm">
        {getScanScheduleLabel(scan.attributes.trigger)}
      </span>
      {scan.attributes.scheduled_at && (
        <DateWithTime dateTime={scan.attributes.scheduled_at} showTime />
      )}
    </div>
  );
}
