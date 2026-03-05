import { cn } from "@/lib/utils";

export const FindingStatusValues = {
  FAIL: "FAIL",
  PASS: "PASS",
  MANUAL: "MANUAL",
  MUTED: "MUTED",
} as const;

export type FindingStatus =
  (typeof FindingStatusValues)[keyof typeof FindingStatusValues];

const STATUS_STYLES = {
  FAIL: "border-bg-fail text-bg-fail",
  PASS: "border-bg-pass text-bg-pass",
  MANUAL: "border-bg-warning text-bg-warning",
  MUTED: "border-text-neutral-tertiary text-text-neutral-tertiary",
} as const;

interface StatusFindingBadgeProps {
  status: FindingStatus;
  size?: "sm" | "md" | "lg";
  value?: string | number;
}

export const StatusFindingBadge = ({
  status,
  value,
}: StatusFindingBadgeProps) => {
  const statusStyle = STATUS_STYLES[status] || STATUS_STYLES.MUTED;
  const displayText =
    status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();

  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded px-0 py-0.5",
        "border-x border-y-0",
        "min-w-[38px] text-center text-xs font-bold",
        statusStyle,
      )}
    >
      {displayText}
      {value !== undefined && `: ${value}`}
    </span>
  );
};
