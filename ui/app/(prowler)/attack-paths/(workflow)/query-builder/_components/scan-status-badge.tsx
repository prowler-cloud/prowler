"use client";

import { Loader2 } from "lucide-react";

import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";
import type { ScanState } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

const BADGE_CONFIG: Record<ScanState, { className: string; label: string }> = {
  [SCAN_STATES.SCHEDULED]: {
    className: "bg-bg-neutral-tertiary text-text-neutral-primary",
    label: "Scheduled",
  },
  [SCAN_STATES.AVAILABLE]: {
    className: "bg-bg-neutral-tertiary text-text-neutral-primary",
    label: "Queued",
  },
  [SCAN_STATES.EXECUTING]: {
    className: "bg-bg-info-secondary text-text-info",
    label: "In Progress",
  },
  [SCAN_STATES.COMPLETED]: {
    className: "bg-bg-pass-secondary text-text-success-primary",
    label: "Completed",
  },
  [SCAN_STATES.FAILED]: {
    className: "bg-bg-fail-secondary text-text-error-primary",
    label: "Failed",
  },
};

interface ScanStatusBadgeProps {
  status: ScanState;
  progress?: number;
}

export const ScanStatusBadge = ({
  status,
  progress = 0,
}: ScanStatusBadgeProps) => {
  const config = BADGE_CONFIG[status];

  const label =
    status === SCAN_STATES.EXECUTING
      ? `${config.label} (${progress}%)`
      : config.label;

  return (
    <Badge className={cn(config.className, "gap-2")}>
      {status === SCAN_STATES.EXECUTING && (
        <Loader2 size={14} className="animate-spin" />
      )}
      <span>{label}</span>
    </Badge>
  );
};
