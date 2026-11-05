"use client";

import { Badge } from "@/components/shadcn";
import { TableLink } from "@/components/shadcn/custom";

interface ResourceCountCellProps {
  count?: number;
  scanId?: string;
}

export function ResourceCountCell({ count, scanId }: ResourceCountCellProps) {
  if (count && count > 0 && scanId) {
    return (
      <TableLink
        href={`/resources?filter[scan]=${encodeURIComponent(scanId)}`}
        label={count.toLocaleString()}
      />
    );
  }

  return (
    <Badge variant="tag" className="rounded text-sm">
      <span className="font-bold">{(count ?? 0).toLocaleString()}</span>
    </Badge>
  );
}
