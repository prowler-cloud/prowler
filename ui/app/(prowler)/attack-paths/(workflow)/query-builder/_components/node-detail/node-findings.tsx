"use client";

import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";
import type { GraphNode } from "@/types/attack-paths";

interface NodeFindingsProps {
  node: GraphNode;
  allNodes?: GraphNode[];
}

/**
 * Node findings section showing related findings for the selected node
 * Displays findings that are connected to the node via HAS_FINDING edges
 */
export const NodeFindings = ({ node, allNodes = [] }: NodeFindingsProps) => {
  // Get finding IDs from the node's findings array (populated by adapter)
  const findingIds = node.findings || [];

  // Get the actual finding nodes
  const findingNodes = allNodes.filter((n) => findingIds.includes(n.id));

  if (findingNodes.length === 0) {
    return null;
  }

  const getSeverityColor = (
    severity?: string | number | boolean | null,
  ): string => {
    const sev = String(severity || "").toLowerCase();
    switch (sev) {
      case "critical":
        return "bg-bg-data-critical";
      case "high":
        return "bg-bg-data-high";
      case "medium":
        return "bg-bg-data-medium";
      case "low":
        return "bg-bg-data-low";
      case "info":
        return "bg-bg-data-info";
      default:
        return "bg-bg-data-muted";
    }
  };

  const getStatusVariant = (
    status?: string | number | boolean | null,
  ): "default" | "destructive" | "secondary" => {
    const st = String(status || "").toUpperCase();
    if (st === "PASS") return "default";
    if (st === "FAIL") return "destructive";
    return "secondary";
  };

  return (
    <ul className="flex flex-col gap-3">
      {findingNodes.map((finding) => (
        <li
          key={finding.id}
          className="border-border-neutral-secondary rounded-lg border p-3"
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                {finding.properties?.severity && (
                  <Badge
                    className={cn(
                      getSeverityColor(finding.properties.severity),
                      "text-text-neutral-primary",
                    )}
                  >
                    {String(finding.properties.severity)}
                  </Badge>
                )}
                <h5 className="dark:text-prowler-theme-pale/90 text-sm font-medium">
                  {String(
                    finding.properties?.finding_id ||
                      finding.properties?.name ||
                      finding.id,
                  )}
                </h5>
              </div>
              <p className="text-text-neutral-tertiary dark:text-text-neutral-tertiary mt-1 text-xs">
                ID: {finding.id}
              </p>
            </div>
            <div className="flex flex-col gap-1">
              <a
                href={`/findings?id=${finding.id}`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`View full finding for ${finding.properties?.finding_id || finding.id}`}
                className="text-text-info dark:text-text-info h-auto p-0 text-xs font-medium hover:underline"
              >
                View Full Finding →
              </a>
              {finding.properties?.status && (
                <Badge variant={getStatusVariant(finding.properties.status)}>
                  {String(finding.properties.status)}
                </Badge>
              )}
            </div>
          </div>
          {finding.properties?.description && (
            <div className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-xs">
              {String(finding.properties.description)}
            </div>
          )}
        </li>
      ))}
    </ul>
  );
};
