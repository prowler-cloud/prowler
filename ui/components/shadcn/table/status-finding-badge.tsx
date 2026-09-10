import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";

export const FindingStatusValues = {
  FAIL: "FAIL",
  PASS: "PASS",
  MANUAL: "MANUAL",
  MUTED: "MUTED",
} as const;

export type FindingStatus =
  (typeof FindingStatusValues)[keyof typeof FindingStatusValues];

type FindingStatusVariant = "error" | "success" | "warning" | "tag";

const STATUS_VARIANT: Record<FindingStatus, FindingStatusVariant> = {
  FAIL: "error",
  PASS: "success",
  MANUAL: "warning",
  MUTED: "tag",
} as const;

type StatusFindingBadgeSize = "sm" | "md" | "lg";

const SIZE_CLASS: Record<StatusFindingBadgeSize, string> = {
  sm: "",
  md: "px-2.5 py-1",
  lg: "px-3 py-1.5 text-sm",
} as const;

interface StatusFindingBadgeProps {
  status: FindingStatus;
  size?: StatusFindingBadgeSize;
  value?: string | number;
  className?: string;
}

export const StatusFindingBadge = ({
  status,
  size = "sm",
  value,
  className,
}: StatusFindingBadgeProps) => {
  const variant = STATUS_VARIANT[status] ?? "tag";
  const displayText =
    status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();

  return (
    <Badge
      variant={variant}
      className={cn("font-bold", SIZE_CLASS[size], className)}
    >
      {displayText}
      {value !== undefined && `: ${value}`}
    </Badge>
  );
};
