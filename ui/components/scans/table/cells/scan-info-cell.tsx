"use client";

import { getScanAlias } from "@/components/scans/scans.utils";
import { EntityInfo } from "@/components/ui/entities";
import type { ScanProps } from "@/types";

export function ScanInfoCell({ scan }: { scan: ScanProps }) {
  return (
    <div className="max-w-[240px] min-w-0">
      <EntityInfo
        entityAlias={getScanAlias(scan)}
        // Synthetic pending rows have a fabricated id; show none until the scan exists.
        entityId={scan.pendingSchedule ? undefined : scan.id}
        idLabel="ID"
      />
    </div>
  );
}
