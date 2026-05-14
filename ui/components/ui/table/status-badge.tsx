import { Chip } from "@heroui/chip";

import { SpinnerIcon } from "@/components/icons";
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

const statusColorMap: Record<
  Status,
  "danger" | "warning" | "success" | "default"
> = {
  available: "default",
  queued: "default",
  scheduled: "warning",
  executing: "default",
  completed: "success",
  failed: "danger",
  cancelled: "danger",
};

export const StatusBadge = ({
  status,
  size = "sm",
  loadingProgress,
  className,
  ...props
}: {
  status: Status;
  size?: "sm" | "md" | "lg";
  loadingProgress?: number;
  className?: string;
}) => {
  const color = statusColorMap[status as keyof typeof statusColorMap];
  const displayLabel = statusDisplayMap[status] || status;

  return (
    <Chip
      className={cn(
        "text-default-600 relative w-full max-w-full border-none text-xs capitalize",
        status === "executing" && "border border-solid border-transparent",
        className,
      )}
      size={size}
      variant="flat"
      color={color}
      {...props}
    >
      {status === "executing" ? (
        <div className="relative flex items-center justify-center gap-1">
          <SpinnerIcon size={16} className="text-default-500 animate-spin" />
          <span className="text-default-500 pointer-events-none text-[0.6rem]">
            {loadingProgress}%
          </span>
          <span>executing</span>
        </div>
      ) : (
        <span className="flex items-center justify-center">{displayLabel}</span>
      )}
    </Chip>
  );
};
