"use client";

import { Card, CardContent } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { AttackPathGraphData } from "@/types/attack-paths";

import { getNodeColor, GRAPH_NODE_COLORS } from "../../_lib/graph-colors";

interface LegendItem {
  label: string;
  color: string;
  description: string;
  icon: string;
}

// Map node labels to human-readable names, descriptions, and icons
const nodeTypeDescriptions = {
  ProwlerFinding: {
    name: "Prowler Finding",
    description: "Security findings from Prowler scans",
    icon: "⚠",
  },
  AWSAccount: {
    name: "AWS Account",
    description: "AWS account root node",
    icon: "☁",
  },
  EC2Instance: {
    name: "EC2 Instance",
    description: "Elastic Compute Cloud instance",
    icon: "🖥",
  },
  S3Bucket: {
    name: "S3 Bucket",
    description: "Simple Storage Service bucket",
    icon: "💾",
  },
  IAMRole: {
    name: "IAM Role",
    description: "Identity and Access Management role",
    icon: "🔑",
  },
} as const;

/**
 * Extract unique node types from graph data
 * @param nodes - Array of graph nodes
 * @returns Array of unique node type labels found in the graph
 */
function extractNodeTypes(
  nodes: AttackPathGraphData["nodes"] | undefined,
): string[] {
  if (!nodes) return [];

  const nodeTypes = new Set<string>();
  nodes.forEach((node) => {
    node.labels.forEach((label) => {
      nodeTypes.add(label);
    });
  });

  return Array.from(nodeTypes).sort();
}

/**
 * Generate legend items from graph data
 * @param nodeTypes - Array of node type labels
 * @returns Array of legend items to display
 */
function generateLegendItems(nodeTypes: string[]): LegendItem[] {
  const items: LegendItem[] = [];
  const seenTypes = new Set<string>();

  nodeTypes.forEach((nodeType) => {
    if (seenTypes.has(nodeType)) return;
    seenTypes.add(nodeType);

    const description =
      nodeTypeDescriptions[nodeType as keyof typeof nodeTypeDescriptions];
    if (description) {
      items.push({
        label: description.name,
        color: getNodeColor([nodeType]),
        description: description.description,
        icon: description.icon,
      });
    } else {
      // For unknown node types, use the type as label and default color
      items.push({
        label: nodeType,
        color: GRAPH_NODE_COLORS.default,
        description: `${nodeType} node`,
        icon: "●",
      });
    }
  });

  return items;
}

interface GraphLegendProps {
  data?: AttackPathGraphData;
}

/**
 * Legend for attack path graph node types
 * Dynamically generates legend items from the actual node types in the graph
 */
export const GraphLegend = ({ data }: GraphLegendProps) => {
  const nodeTypes = extractNodeTypes(data?.nodes);
  const legendItems = generateLegendItems(nodeTypes);

  if (legendItems.length === 0) {
    return null;
  }

  return (
    <Card className="w-fit border-0">
      <CardContent className="gap-3 p-4">
        <div className="flex flex-col items-center gap-4 lg:flex-row lg:flex-wrap">
          <TooltipProvider>
            {legendItems.map((item) => (
              <Tooltip key={item.label}>
                <TooltipTrigger asChild>
                  <div
                    className="flex cursor-help items-center gap-2"
                    role="img"
                    aria-label={`${item.label}: ${item.description}`}
                  >
                    <div className="relative flex-shrink-0">
                      <div
                        className="h-5 w-5 rounded-full opacity-80"
                        style={{ backgroundColor: item.color }}
                        aria-hidden="true"
                      />
                      <div className="absolute top-0 left-0 flex h-5 w-5 items-center justify-center text-xs">
                        {item.icon}
                      </div>
                    </div>
                    <span className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
                      {item.label}
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>{item.description}</TooltipContent>
              </Tooltip>
            ))}
          </TooltipProvider>
        </div>
      </CardContent>
    </Card>
  );
};
