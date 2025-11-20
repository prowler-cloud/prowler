"use client";

import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";
import { InfoField } from "@/components/ui/entities";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import type { GraphNode, GraphNodePropertyValue } from "@/types/attack-paths";

import { formatNodeLabels } from "../../_lib";

interface NodeOverviewProps {
  node: GraphNode;
}

/**
 * Node overview section showing basic node information
 */
export const NodeOverview = ({ node }: NodeOverviewProps) => {
  const renderValue = (value: GraphNodePropertyValue) => {
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    return String(value);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <InfoField label="Node ID" variant="simple">
          <CodeSnippet value={node.id} />
        </InfoField>
        <InfoField label="Type">{formatNodeLabels(node.labels)}</InfoField>
      </div>

      {/* Display all properties */}
      <div className="mt-4 border-t border-gray-200 pt-4 dark:border-gray-700">
        <h4 className="dark:text-prowler-theme-pale/90 mb-3 text-sm font-semibold">
          Properties
        </h4>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {Object.entries(node.properties).map(([key, value]) => {
            // Skip internal properties
            if (key.startsWith("_")) {
              return null;
            }

            // Format timestamp values
            const isTimestamp =
              key.includes("date") ||
              key.includes("time") ||
              key.includes("at") ||
              key.includes("seen");

            return (
              <InfoField key={key} label={formatPropertyName(key)}>
                {isTimestamp && typeof value === "number" ? (
                  <DateWithTime
                    inline
                    dateTime={new Date(value).toISOString()}
                  />
                ) : isTimestamp &&
                  typeof value === "string" &&
                  value.match(/^\d+$/) ? (
                  <DateWithTime
                    inline
                    dateTime={new Date(parseInt(value)).toISOString()}
                  />
                ) : typeof value === "object" ? (
                  <code className="text-xs">
                    {JSON.stringify(value).substring(0, 50)}...
                  </code>
                ) : (
                  renderValue(value)
                )}
              </InfoField>
            );
          })}
        </div>
      </div>
    </div>
  );
};

// Helper function to format property names
function formatPropertyName(name: string): string {
  return name
    .replace(/([A-Z])/g, " $1")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (l) => l.toUpperCase())
    .trim();
}
