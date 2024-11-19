import { Chip } from "@nextui-org/react";
import React from "react";

export type FindingStatus = "FAIL" | "PASS" | "MANUAL" | "MUTED";

const statusColorMap: Record<
  FindingStatus,
  "danger" | "warning" | "success" | "default"
> = {
  FAIL: "danger",
  PASS: "success",
  MANUAL: "warning",
  MUTED: "default",
};

export const StatusFindingBadge = ({
  status,
  size = "sm",
  ...props
}: {
  status: FindingStatus;
  size?: "sm" | "md" | "lg";
}) => {
  const color = statusColorMap[status];

  return (
    <Chip
      className="gap-1 border-none px-2 py-1 capitalize text-default-600"
      size={size}
      variant="flat"
      color={color}
      {...props}
    >
      {status}
    </Chip>
  );
};
