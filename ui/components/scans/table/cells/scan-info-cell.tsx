"use client";

import { getScanAlias } from "@/components/scans/scans.utils";
import {
  Badge,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { EntityInfo } from "@/components/shadcn/entities";
import type { ScanProps } from "@/types";

export function ScanInfoCell({ scan }: { scan: ScanProps }) {
  // Synthetic pending rows have no Scan behind them yet, so there is no id.
  if (scan.pendingSchedule) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge variant="tag">Pending</Badge>
        </TooltipTrigger>
        <TooltipContent>
          This scan has not been created yet. Its details will appear after the
          first scheduled run.
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <div className="flex max-w-[240px] min-w-0 items-center gap-2">
      <EntityInfo
        entityAlias={getScanAlias(scan)}
        entityId={scan.id}
        idLabel="ID"
      />
      {scan.attributes.is_partial && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="tag" tabIndex={0}>
              Partial
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            Re-checked a few resources. Overviews still reflect the latest full
            scan.
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}
