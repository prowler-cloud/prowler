import { Chip } from "@nextui-org/react";
import React from "react";

type Status =
  | "completed"
  | "pending"
  | "cancelled"
  | "fail"
  | "success"
  | "muted";

export const statusColorMap: Record<
  Status,
  "success" | "danger" | "warning" | "default"
> = {
  completed: "success",
  pending: "warning",
  cancelled: "danger",
  fail: "danger",
  success: "success",
  muted: "default",
};

export const StatusBadge = ({ status }: { status: Status }) => {
  return (
    <Chip
      className="capitalize border-none gap-1 text-default-600"
      // eslint-disable-next-line security/detect-object-injection
      color={statusColorMap[status]}
      size="sm"
      variant="flat"
    >
      {status}
    </Chip>
  );
};
