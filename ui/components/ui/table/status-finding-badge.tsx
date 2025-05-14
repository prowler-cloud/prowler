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
      className="border-none px-2 py-0"
      size={size}
      variant="flat"
      color={color}
      {...props}
    >
      <span className="text-xs font-light tracking-wide text-default-600">
        {status.charAt(0).toUpperCase() + status.slice(1).toLowerCase()}
      </span>
    </Chip>
  );
};
