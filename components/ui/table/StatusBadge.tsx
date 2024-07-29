import { Chip } from "@nextui-org/react";
import React from "react";

type Status = "completed" | "pending" | "cancelled";

export const statusColorMap: Record<Status, "success" | "danger" | "warning"> =
  {
    completed: "success",
    pending: "warning",
    cancelled: "danger",
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
