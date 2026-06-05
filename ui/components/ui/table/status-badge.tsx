import { SpinnerIcon } from "@/components/icons";
import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

export type Status =
  | "available"
  | "queued"
  | "scheduled"
  | "executing"
  | "completed"
  | "failed"
  | "cancelled";

const statusDisplayMap: Record<Status, string> = {
  available: "Queued",
  queued: "Queued",
  scheduled: "scheduled",
  executing: "executing",
  completed: "completed",
  failed: "failed",
  cancelled: "cancelled",
};

type StatusBadgeVariant = "tag" | "warning" | "success" | "error";

const statusVariantMap: Record<Status, StatusBadgeVariant> = {
  available: "tag",
  queued: "tag",
  scheduled: "warning",
  executing: "tag",
  completed: "success",
  failed: "error",
  cancelled: "error",
};

type StatusBadgeSize = "sm" | "md" | "lg";

const STATUS_BADGE_SIZE_CLASS: Record<StatusBadgeSize, string> = {
  sm: "",
  md: "px-2.5 py-1",
  lg: "px-3 py-1.5 text-sm",
};

interface StatusBadgeProps {
  status: Status;
  size?: StatusBadgeSize;
  loadingProgress?: number;
  className?: string;
}

export const StatusBadge = ({
  status,
  size = "sm",
  loadingProgress,
  className,
}: StatusBadgeProps) => {
  const variant = statusVariantMap[status];
  const label = statusDisplayMap[status] || status;

  return (
    <Badge
      variant={variant}
      className={cn(
        "max-w-full capitalize",
        STATUS_BADGE_SIZE_CLASS[size],
        className,
      )}
    >
      {status === "executing" ? (
        <span className="inline-flex items-center gap-1">
          <SpinnerIcon
            size={12}
            className="animate-spin motion-reduce:animate-none"
          />
          {loadingProgress !== undefined && (
            <span className="text-[0.6rem]">{loadingProgress}%</span>
          )}
          <span>executing</span>
        </span>
      ) : (
        label
      )}
    </Badge>
  );
};
