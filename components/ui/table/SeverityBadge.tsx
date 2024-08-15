import { Chip } from "@nextui-org/react";
import clsx from "clsx";
import React from "react";

import { AlertIcon } from "@/components/icons";

type Severity = "critical" | "high" | "medium" | "low";

const severityIconMap = {
  critical: <AlertIcon size={14} className="mr-1" />,
} as const;

const getSeverityColor = (
  severity: Severity,
): "danger" | "warning" | "default" => {
  switch (severity) {
    case "critical":
      return "danger";
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "default";
    default:
      return "default"; // this is a fallback, though unnecessary due to typing
  }
};

const getSeverityIcon = (severity: Severity): React.ReactNode | null => {
  return severity === "critical" ? severityIconMap.critical : null;
};

export const SeverityBadge = ({ severity }: { severity: Severity }) => {
  const color = getSeverityColor(severity);

  return (
    <Chip
      className={clsx("capitalize border-none gap-1 text-default-600", {
        "bg-rose-700/20": severity === "critical",
      })}
      size="sm"
      variant="flat"
      color={color}
      endContent={getSeverityIcon(severity)}
    >
      {severity}
    </Chip>
  );
};
