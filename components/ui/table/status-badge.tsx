import { Chip } from "@nextui-org/react";
import React from "react";

type Status =
  | "completed"
  | "pending"
  | "cancelled"
  | "fail"
  | "success"
  | "muted"
  | "active"
  | "inactive";

const statusColorMap: Record<
  Status,
  "danger" | "warning" | "success" | "default"
> = {
  completed: "success",
  pending: "warning",
  cancelled: "danger",
  fail: "danger",
  success: "success",
  muted: "default",
  active: "success",
  inactive: "default",
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
