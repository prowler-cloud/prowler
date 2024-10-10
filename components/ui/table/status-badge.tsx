import { Chip } from "@nextui-org/react";
import React from "react";

type Status =
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

export const StatusBadge = ({ status }: { status: Status }) => {
  const color = statusColorMap[status as keyof typeof statusColorMap];

  return (
    <Chip
      className="gap-1 border-none capitalize text-default-600"
      size="sm"
      variant="flat"
      color={color}
    >
      {status}
    </Chip>
  );
};
