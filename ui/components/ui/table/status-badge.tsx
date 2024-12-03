import { Chip, CircularProgress } from "@nextui-org/react";
import React from "react";

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
  ...props
}: {
  status: Status;
  size?: "sm" | "md" | "lg";
  loadingProgress?: number;
}) => {
  const color = statusColorMap[status as keyof typeof statusColorMap];

  return (
    <Chip
      className="gap-1 border-none px-2 py-2 capitalize text-default-600"
      size={size}
      variant="flat"
      color={color}
      {...props}
    >
      {status === "executing" ? (
        <div className="flex items-center gap-1">
          <CircularProgress
            size="md"
            classNames={{
              svg: "h-7 w-7 drop-shadow-md text-prowler-theme-green",
              indicator: "stroke-prowler-theme-green",
              track: "stroke-prowler-theme-green/10",
            }}
            aria-label="Loading..."
            value={loadingProgress}
            showValueLabel={true}
          />
          executing
        </div>
      ) : (
        status
      )}
    </Chip>
  );
};
