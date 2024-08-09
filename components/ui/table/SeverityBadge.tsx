import { Chip } from "@nextui-org/react";
import React from "react";

import { AlertIcon } from "@/components/icons";

type Severity = "critical" | "high" | "medium" | "low";

const severityColorMap: Record<
  Severity,
  | "text-white bg-red-800"
  | "text-white bg-red-600"
  | "text-white bg-orange-500"
  | "bg-yellow-200"
> = {
  critical: "text-white bg-red-800",
  high: "text-white bg-red-600",
  medium: "text-white bg-orange-500",
  low: "bg-yellow-200",
};

const severityIconMap: Partial<Record<Severity, React.ReactNode>> = {
  critical: <AlertIcon size={14} className="mr-1" />,
};

const getSeverityColor: (severity: Severity) => string = (severity) =>
  // eslint-disable-next-line security/detect-object-injection
  severityColorMap[severity];

const getSeverityIcon: (severity: Severity) => React.ReactNode | null = (
  severity,
) =>
  // eslint-disable-next-line security/detect-object-injection
  severityIconMap[severity] || null;

export const SeverityBadge = ({ severity }: { severity: Severity }) => {
  return (
    <Chip
      classNames={{
        base: `capitalize border-none gap-1 text-gray-600 ${getSeverityColor(severity)}`,
        content: "font-semibold",
      }}
      size="sm"
      variant="flat"
      endContent={getSeverityIcon(severity)}
    >
      {severity}
    </Chip>
  );
};
