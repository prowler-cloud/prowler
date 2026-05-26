"use client";

import { getScanAlias } from "@/components/scans/scans-table.utils";
import { EntityInfo } from "@/components/ui/entities";
import type { ScanProps } from "@/types";

export function ScanInfoCell({ scan }: { scan: ScanProps }) {
  return (
    <div className="max-w-[240px] min-w-0">
      <EntityInfo
        entityAlias={getScanAlias(scan)}
        entityId={scan.id}
        idLabel="ID"
      />
    </div>
  );
}
