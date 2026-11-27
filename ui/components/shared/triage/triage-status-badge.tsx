import { TRIAGE_STATUS_TEXT_CLASS } from "@/lib/triage";
import { cn } from "@/lib/utils";
import { FINDING_TRIAGE_STATUS_LABELS } from "@/types/findings-triage";

import type { TriageStatusBadgeProps } from "./types";

export function TriageStatusBadge({
  status,
  showLabel = true,
}: TriageStatusBadgeProps) {
  return (
    <div className="flex items-center gap-1">
      {showLabel && (
        <span className="text-text-neutral-tertiary text-xs">Triage:</span>
      )}
      <span
        className={cn("text-xs font-medium", TRIAGE_STATUS_TEXT_CLASS[status])}
      >
        {FINDING_TRIAGE_STATUS_LABELS[status]}
      </span>
    </div>
  );
}
