import { Chip } from "@heroui/chip";
import clsx from "clsx";

import { SpinnerIcon } from "@/components/icons";

const STATUS = {
  available: "available",
  scheduled: "scheduled",
  executing: "executing",
  completed: "completed",
  failed: "failed",
  cancelled: "cancelled",
} as const;

export type Status = (typeof STATUS)[keyof typeof STATUS];

const statusColorMap: Record<
  Status,
  "danger" | "warning" | "success" | "default"
> = {
  available: "default",
  scheduled: "warning",
  executing: "default",
  completed: "success",
  failed: "danger",
  cancelled: "danger",
};

const statusDisplayMap: Record<Status, string> = {
  available: "queued",
  scheduled: "scheduled",
  executing: "executing",
  completed: "completed",
  failed: "failed",
  cancelled: "cancelled",
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
      className={clsx(
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
