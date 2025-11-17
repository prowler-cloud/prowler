"use client";

import { Chip } from "@heroui/chip";
import { Link as HeroUILink } from "@heroui/link";

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "PASS" | "FAIL" | "MANUAL";
}

interface NodeRemediationProps {
  findings: Finding[];
}

/**
 * Node remediation section showing related Prowler findings
 */
export const NodeRemediation = ({ findings }: NodeRemediationProps) => {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "danger";
      case "high":
        return "warning";
      case "medium":
        return "secondary";
      case "low":
        return "default";
      default:
        return "default";
    }
  };

  const getStatusColor = (status: string) => {
    if (status === "PASS") return "success";
    if (status === "FAIL") return "danger";
    return "default";
  };

  return (
    <div className="flex flex-col gap-3">
      {findings.map((finding) => (
        <div
          key={finding.id}
          className="rounded-lg border border-gray-200 p-3 dark:border-gray-700"
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <h5 className="dark:text-prowler-theme-pale/90 text-sm font-medium">
                {finding.title}
              </h5>
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                ID: {finding.id.substring(0, 12)}...
              </p>
            </div>
            <div className="flex flex-col gap-1">
              <Chip
                size="sm"
                variant="flat"
                color={getSeverityColor(finding.severity)}
                className="capitalize"
              >
                {finding.severity}
              </Chip>
              <Chip
                size="sm"
                variant="flat"
                color={getStatusColor(finding.status)}
              >
                {finding.status}
              </Chip>
            </div>
          </div>
          <div className="mt-2">
            <HeroUILink
              href={`/findings?id=${finding.id}`}
              size="sm"
              target="_blank"
              rel="noopener noreferrer"
            >
              View Full Finding →
            </HeroUILink>
          </div>
        </div>
      ))}
    </div>
  );
};
