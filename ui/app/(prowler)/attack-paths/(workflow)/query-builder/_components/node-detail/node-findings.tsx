"use client";

import { SeverityBadge } from "@/components/ui/table/severity-badge";
import type { GraphNode } from "@/types/attack-paths";

const SEVERITY_LEVELS = {
  informational: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
} as const;

type Severity = (typeof SEVERITY_LEVELS)[keyof typeof SEVERITY_LEVELS];

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

  const normalizeSeverity = (
    severity?: string | number | boolean | string[] | number[] | null,
  ): Severity => {
    const sev = String(
      Array.isArray(severity) ? severity[0] : severity || "",
    ).toLowerCase();
    if (sev in SEVERITY_LEVELS) {
      return sev as Severity;
    }
    return "informational";
  };

  return (
    <ul className="flex flex-col gap-3">
      {findingNodes.map((finding) => {
        // Get the finding name (check_title preferred, then name)
        const findingName = String(
          finding.properties?.check_title ||
            finding.properties?.name ||
            finding.properties?.finding_id ||
            "Unknown Finding",
        );
        // Use properties.id for display, fallback to graph node id
        const findingId = String(finding.properties?.id || finding.id);

        return (
          <li
            key={finding.id}
            className="border-border-neutral-secondary rounded-lg border p-3"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  {finding.properties?.severity && (
                    <SeverityBadge
                      severity={normalizeSeverity(finding.properties.severity)}
                    />
                  )}
                  <h5 className="dark:text-prowler-theme-pale/90 text-sm font-medium">
                    {findingName}
                  </h5>
                </div>
                <p className="text-text-neutral-tertiary dark:text-text-neutral-tertiary mt-1 text-xs">
                  ID: {findingId}
                </p>
              </div>
              <a
                href={`/findings?id=${findingId}`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`View full finding for ${findingName}`}
                className="text-text-info dark:text-text-info h-auto shrink-0 p-0 text-xs font-medium hover:underline"
              >
                View Full Finding →
              </a>
            </div>
            {finding.properties?.description && (
              <div className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-xs">
                {String(finding.properties.description)}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
};
