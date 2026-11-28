"use client";

import { Badge, Progress } from "@/components/shadcn";
import type { ScanProps } from "@/types";

export function ProgressCell({ scan }: { scan: ScanProps }) {
  const progress = scan.attributes.progress ?? 0;
  const isQueued = scan.attributes.state === "available";

  if (scan.attributes.waiting_for_credentials) {
    return <Badge variant="warning">Waiting for updated AWS credentials</Badge>;
  }

  if (isQueued) {
    return <Badge variant="warning">Queued for scan</Badge>;
  }

  return (
    <div className="flex min-w-[220px] items-center gap-3">
      <Progress value={progress} className="h-2 min-w-[140px]" />
      <span className="text-text-neutral-secondary min-w-9 text-xs font-medium">
        {progress}%
      </span>
    </div>
  );
}
