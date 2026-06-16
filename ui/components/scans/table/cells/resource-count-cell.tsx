"use client";

import { Badge } from "@/components/shadcn";

export function ResourceCountCell({ count }: { count?: number }) {
  return (
    <Badge variant="tag" className="rounded text-sm">
      <span className="font-bold">{(count ?? 0).toLocaleString()}</span>
    </Badge>
  );
}
