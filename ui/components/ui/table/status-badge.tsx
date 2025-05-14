import { Chip } from "@nextui-org/react";
import clsx from "clsx";
import React from "react";

import { SpinnerIcon } from "@/components/icons";

export type Status =
  | "available"
  | "scheduled"
  | "executing"
  | "completed"
  | "failed"
  | "cancelled";

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

  return (
    <Chip
      className={clsx(
        "relative w-full max-w-full border-none text-xs capitalize text-default-600",
        status === "executing" && "border-1 border-solid border-transparent",
        className,
      )}
      size={size}
      variant="flat"
      color={color}
      {...props}
    >
      {status === "executing" ? (
        <div className="relative flex items-center justify-center gap-1">
          <SpinnerIcon size={16} className="animate-spin text-default-500" />
          <span className="pointer-events-none text-[0.6rem] text-default-500">
            {loadingProgress}%
          </span>
          <span>executing</span>
        </div>
      ) : (
        <span className="flex items-center justify-center">{status}</span>
      )}
    </Chip>
  );
};
