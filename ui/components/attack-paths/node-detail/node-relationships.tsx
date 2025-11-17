"use client";

import type { GraphEdge } from "@/types/attack-paths";

interface NodeRelationshipsProps {
  incomingEdges: GraphEdge[];
  outgoingEdges: GraphEdge[];
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
              <div
                key={edge.id}
                className="flex items-center justify-between rounded border border-gray-200 p-2 dark:border-gray-700"
              >
                <code className="text-xs">
                  {typeof edge.target === "string"
                    ? edge.target.substring(0, 30)
                    : String(edge.target).substring(0, 30)}
                </code>
                <span className="rounded bg-blue-100 px-2 py-1 text-xs font-medium text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                  {edge.type}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-500 dark:text-gray-400">
            No outgoing relationships
          </p>
        )}
      </div>

      {/* Incoming Relationships */}
      <div className="border-t border-gray-200 pt-6 dark:border-gray-700">
        <h4 className="dark:text-prowler-theme-pale/90 mb-3 text-sm font-semibold">
          Incoming Relationships ({incomingEdges.length})
        </h4>
        {incomingEdges.length > 0 ? (
          <div className="space-y-2">
            {incomingEdges.map((edge) => (
              <div
                key={edge.id}
                className="flex items-center justify-between rounded border border-gray-200 p-2 dark:border-gray-700"
              >
                <code className="text-xs">
                  {typeof edge.source === "string"
                    ? edge.source.substring(0, 30)
                    : String(edge.source).substring(0, 30)}
                </code>
                <span className="rounded bg-green-100 px-2 py-1 text-xs font-medium text-green-800 dark:bg-green-900 dark:text-green-200">
                  {edge.type}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-500 dark:text-gray-400">
            No incoming relationships
          </p>
        )}
      </div>
    </div>
  );
};
