"use client";

import { cn } from "@/lib/utils";
import type { GraphEdge } from "@/types/attack-paths";

interface NodeRelationshipsProps {
  incomingEdges: GraphEdge[];
  outgoingEdges: GraphEdge[];
}

/**
 * Format edge type to human-readable label
 * e.g., "HAS_FINDING" -> "Has Finding"
 */
function formatEdgeType(edgeType: string): string {
  return edgeType
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

interface EdgeItemProps {
  edge: GraphEdge;
  isOutgoing: boolean;
}

/**
 * Reusable edge item component
 */
function EdgeItem({ edge, isOutgoing }: EdgeItemProps) {
  const targetId =
    typeof edge.target === "string" ? edge.target : String(edge.target);
  const sourceId =
    typeof edge.source === "string" ? edge.source : String(edge.source);
  const displayId = (isOutgoing ? targetId : sourceId).substring(0, 30);

  return (
    <div
      key={edge.id}
      className="border-border-neutral-tertiary dark:border-border-neutral-tertiary flex items-center justify-between rounded border p-2"
    >
      <code className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
        {displayId}
      </code>
      <span
        className={cn(
          "rounded px-2 py-1 text-xs font-medium",
          isOutgoing
            ? "bg-bg-data-info text-text-neutral-primary dark:text-text-neutral-primary"
            : "bg-bg-pass-primary text-text-neutral-primary dark:text-text-neutral-primary",
        )}
      >
        {formatEdgeType(edge.type)}
      </span>
    </div>
  );
}

/**
 * Node relationships section showing incoming and outgoing edges
 */
export const NodeRelationships = ({
  incomingEdges,
  outgoingEdges,
}: NodeRelationshipsProps) => {
  return (
    <div className="flex flex-col gap-6">
      {/* Outgoing Relationships */}
      <div>
        <h4 className="dark:text-prowler-theme-pale/90 mb-3 text-sm font-semibold">
          Outgoing Relationships ({outgoingEdges.length})
        </h4>
        {outgoingEdges.length > 0 ? (
          <div className="space-y-2">
            {outgoingEdges.map((edge) => (
              <EdgeItem key={edge.id} edge={edge} isOutgoing />
            ))}
          </div>
        ) : (
          <p className="text-text-neutral-tertiary dark:text-text-neutral-tertiary text-xs">
            No outgoing relationships
          </p>
        )}
      </div>

      {/* Incoming Relationships */}
      <div className="border-border-neutral-tertiary dark:border-border-neutral-tertiary border-t pt-6">
        <h4 className="dark:text-prowler-theme-pale/90 mb-3 text-sm font-semibold">
          Incoming Relationships ({incomingEdges.length})
        </h4>
        {incomingEdges.length > 0 ? (
          <div className="space-y-2">
            {incomingEdges.map((edge) => (
              <EdgeItem key={edge.id} edge={edge} isOutgoing={false} />
            ))}
          </div>
        ) : (
          <p className="text-text-neutral-tertiary dark:text-text-neutral-tertiary text-xs">
            No incoming relationships
          </p>
        )}
      </div>
    </div>
  );
};
