"use client";

import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";
import type { GraphNode } from "@/types/attack-paths";

interface NodeResourcesProps {
  node: GraphNode;
  allNodes?: GraphNode[];
}

/**
 * Node resources section showing affected resources for the selected finding node
 * Displays resources that are connected to the finding node via HAS_FINDING edges
 */
export const NodeResources = ({ node, allNodes = [] }: NodeResourcesProps) => {
  // Get resource IDs from the node's resources array (populated by adapter)
  const resourceIds = node.resources || [];

  // Get the actual resource nodes
  const resourceNodes = allNodes.filter((n) => resourceIds.includes(n.id));

  if (resourceNodes.length === 0) {
    return null;
  }

  const getResourceTypeColor = (labels: string[]): string => {
    const label = (labels[0] || "").toLowerCase();
    switch (label) {
      case "s3bucket":
      case "awsaccount":
      case "ec2instance":
      case "iamrole":
      case "lambdafunction":
      case "securitygroup":
        return "bg-bg-data-aws";
      default:
        return "bg-bg-data-muted";
    }
  };

  return (
    <ul className="flex flex-col gap-3">
      {resourceNodes.map((resource) => {
        // Use properties.id for display, fallback to graph node id
        const resourceId = String(resource.properties?.id || resource.id);

        return (
          <li
            key={resource.id}
            className="border-border-neutral-secondary rounded-lg border p-3"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  {resource.labels && (
                    <Badge
                      className={cn(
                        getResourceTypeColor(resource.labels),
                        "text-text-neutral-primary",
                      )}
                    >
                      {resource.labels[0]}
                    </Badge>
                  )}
                  <h5 className="dark:text-prowler-theme-pale/90 text-sm font-medium">
                    {String(resource.properties?.name || resourceId)}
                  </h5>
                </div>
                <p className="text-text-neutral-tertiary dark:text-text-neutral-tertiary mt-1 text-xs">
                  ID: {resourceId}
                </p>
              </div>
            </div>
            {resource.properties?.arn && (
              <div className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-xs">
                ARN: {String(resource.properties.arn)}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
};
