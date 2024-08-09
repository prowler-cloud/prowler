import { Chip } from "@nextui-org/react";
import React from "react";

type Status =
  | "completed"
  | "pending"
  | "cancelled"
  | "fail"
  | "success"
  | "muted";

const statusColorMap: Record<
  Status,
  | "text-white bg-green-600"
  | "bg-yellow-200"
  | "text-white bg-red-600"
  | "bg-gray-300"
> = {
  completed: "text-white bg-green-600",
  pending: "bg-yellow-200",
  cancelled: "text-white bg-red-600",
  fail: "text-white bg-red-600",
  success: "text-white bg-green-600",
  muted: "bg-gray-300",
};

const getStatusColor: (status: Status) => string = (status) =>
  // eslint-disable-next-line security/detect-object-injection
  statusColorMap[status];

export const StatusBadge = ({ status }: { status: Status }) => {
  return (
    <Chip
      classNames={{
        base: `capitalize border-none gap-1 text-gray-600 ${getStatusColor(status)}`,
        content: "font-semibold",
      }}
      size="sm"
      variant="solid"
    >
      {status}
    </Chip>
  );
};
