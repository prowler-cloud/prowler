"use client";

import { CalendarClock, Download, Eye, XCircle } from "lucide-react";
import { useRouter } from "next/navigation";

import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { useToast } from "@/components/ui";
import { toLocalDateString } from "@/lib/date-utils";
import { downloadScanZip } from "@/lib/helper";
import { SCAN_STATE, type ScanProps } from "@/types";

interface ScanJobsRowActionsProps {
  scan: ScanProps;
}

export function ScanJobsRowActions({ scan }: ScanJobsRowActionsProps) {
  const router = useRouter();
  const { toast } = useToast();
  const scanState = scan.attributes.state;
  const isCompleted = scanState === "completed";
  const canCancel =
    scanState === SCAN_STATE.AVAILABLE ||
    scanState === SCAN_STATE.SCHEDULED ||
    scanState === SCAN_STATE.EXECUTING;
  const scanDate = toLocalDateString(scan.attributes.completed_at);

  const openFindings = () => {
    if (!isCompleted || !scanDate) return;
    router.push(
      `/findings?filter[scan]=${scan.id}&filter[inserted_at]=${scanDate}&filter[status__in]=FAIL`,
    );
  };

  return (
    <div className="flex items-center justify-end">
      <ActionDropdown>
        {isCompleted && (
          <>
            <ActionDropdownItem
              icon={<Eye />}
              label="View Findings"
              onSelect={openFindings}
              disabled={!scanDate}
            />
            <ActionDropdownItem
              icon={<Download />}
              label="Download Findings"
              onSelect={() => downloadScanZip(scan.id, toast)}
            />
          </>
        )}
        <ActionDropdownItem
          icon={<CalendarClock />}
          label="Edit Scan Schedule"
          disabled
        />
        {canCancel && (
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<XCircle />}
              label="Cancel Scan"
              destructive
            />
          </ActionDropdownDangerZone>
        )}
      </ActionDropdown>
    </div>
  );
}
