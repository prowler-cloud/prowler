"use client";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Spinner } from "@/components/shadcn/spinner/spinner";

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "PASS" | "FAIL" | "MANUAL";
}

interface NodeRemediationProps {
  findings: Finding[];
  onViewFinding?: (findingId: string) => void;
  viewFindingLoading?: boolean;
}

/**
 * Node remediation section showing related Prowler findings
 */
export const NodeRemediation = ({
  findings,
  onViewFinding,
  viewFindingLoading = false,
}: NodeRemediationProps) => {
  const getSeverityVariant = (severity: string) => {
    switch (severity) {
      case "critical":
        return "destructive";
      case "high":
        return "default";
      case "medium":
        return "secondary";
      case "low":
        return "outline";
      default:
        return "default";
    }
  };

  const getStatusVariant = (status: string) => {
    if (status === "PASS") return "default";
    if (status === "FAIL") return "destructive";
    return "secondary";
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
              <Badge variant={getSeverityVariant(finding.severity)}>
                {finding.severity}
              </Badge>
              <Badge variant={getStatusVariant(finding.status)}>
                {finding.status}
              </Badge>
            </div>
          </div>
          <div className="mt-2">
            <Button
              variant="link"
              size="sm"
              onClick={() => onViewFinding?.(finding.id)}
              disabled={viewFindingLoading}
              aria-label={`View full finding for ${finding.title}`}
              className="text-text-info dark:text-text-info h-auto p-0 text-sm transition-all hover:opacity-80 dark:hover:opacity-80"
            >
              {viewFindingLoading ? (
                <Spinner className="size-4" />
              ) : (
                "View Full Finding →"
              )}
            </Button>
          </div>
        </div>
      ))}
    </div>
  );
};
