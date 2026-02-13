"use client";

import { useTheme } from "next-themes";

import { Card, CardContent } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { AttackPathGraphData } from "@/types/attack-paths";

import {
  getNodeBorderColor,
  getNodeColor,
  GRAPH_EDGE_COLOR_DARK,
  GRAPH_EDGE_COLOR_LIGHT,
  GRAPH_NODE_BORDER_COLORS,
  GRAPH_NODE_COLORS,
} from "../../_lib/graph-colors";

interface LegendItem {
  label: string;
  color: string;
  borderColor: string;
  description: string;
  shape: "rectangle" | "hexagon" | "cloud";
}

// Map node labels to human-readable names and descriptions
const nodeTypeDescriptions: Record<
  string,
  { name: string; description: string }
> = {
  // Findings
  ProwlerFinding: {
    name: "Finding",
    description: "Security findings from Prowler scans",
  },
  // AWS Account
  AWSAccount: {
    name: "AWS Account",
    description: "AWS account root node",
  },
  // Compute
  EC2Instance: {
    name: "EC2 Instance",
    description: "Elastic Compute Cloud instance",
  },
  LambdaFunction: {
    name: "Lambda Function",
    description: "AWS Lambda serverless function",
  },
  // Storage
  S3Bucket: {
    name: "S3 Bucket",
    description: "Simple Storage Service bucket",
  },
  // IAM
  IAMRole: {
    name: "IAM Role",
    description: "Identity and Access Management role",
  },
  IAMPolicy: {
    name: "IAM Policy",
    description: "Identity and Access Management policy",
  },
  AWSRole: {
    name: "AWS Role",
    description: "AWS IAM role",
  },
  AWSPolicy: {
    name: "AWS Policy",
    description: "AWS IAM policy",
  },
  AWSInlinePolicy: {
    name: "AWS Inline Policy",
    description: "AWS IAM inline policy",
  },
  AWSPolicyStatement: {
    name: "AWS Policy Statement",
    description: "AWS IAM policy statement",
  },
  AWSPrincipal: {
    name: "AWS Principal",
    description: "AWS IAM principal entity",
  },
  // Networking
  SecurityGroup: {
    name: "Security Group",
    description: "AWS security group for network access control",
  },
  EC2SecurityGroup: {
    name: "EC2 Security Group",
    description: "EC2 security group for network access control",
  },
  IpPermissionInbound: {
    name: "IP Permission Inbound",
    description: "Inbound IP permission rule",
  },
  IpRule: {
    name: "IP Rule",
    description: "IP address rule",
  },
  Internet: {
    name: "Internet",
    description: "Internet gateway or public access",
  },
  // Tags
  AWSTag: {
    name: "AWS Tag",
    description: "AWS resource tag",
  },
  Tag: {
    name: "Tag",
    description: "Resource tag",
  },
};

/**
 * Extract unique node types from graph data
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
 * Severity legend items - colors work in both light and dark themes
 */
const severityLegendItems: LegendItem[] = [
  {
    label: "Critical",
    color: GRAPH_NODE_COLORS.critical,
    borderColor: GRAPH_NODE_BORDER_COLORS.critical,
    description: "Critical severity finding",
    shape: "hexagon",
  },
  {
    label: "High",
    color: GRAPH_NODE_COLORS.high,
    borderColor: GRAPH_NODE_BORDER_COLORS.high,
    description: "High severity finding",
    shape: "hexagon",
  },
  {
    label: "Medium",
    color: GRAPH_NODE_COLORS.medium,
    borderColor: GRAPH_NODE_BORDER_COLORS.medium,
    description: "Medium severity finding",
    shape: "hexagon",
  },
  {
    label: "Low",
    color: GRAPH_NODE_COLORS.low,
    borderColor: GRAPH_NODE_BORDER_COLORS.low,
    description: "Low severity finding",
    shape: "hexagon",
  },
];

/**
 * Generate legend items from graph data
 */
function generateLegendItems(
  nodeTypes: string[],
  hasFindings: boolean,
): LegendItem[] {
  const items: LegendItem[] = [];
  const seenTypes = new Set<string>();

  // Add severity items if there are findings
  if (hasFindings) {
    items.push(...severityLegendItems);
  }

  // Helper to format unknown node types (e.g., "AWSPolicyStatement" -> "AWS Policy Statement")
  const formatNodeTypeName = (nodeType: string): string => {
    return nodeType
      .replace(/([A-Z])/g, " $1") // Add space before capitals
      .replace(/^ /, "") // Remove leading space
      .replace(/AWS /g, "AWS ") // Keep AWS together
      .replace(/EC2 /g, "EC2 ") // Keep EC2 together
      .replace(/S3 /g, "S3 ") // Keep S3 together
      .replace(/IAM /g, "IAM ") // Keep IAM together
      .replace(/IP /g, "IP ") // Keep IP together
      .trim();
  };

  nodeTypes.forEach((nodeType) => {
    if (seenTypes.has(nodeType)) return;
    seenTypes.add(nodeType);

    // Skip findings - we show severity colors instead
    const isFinding = nodeType.toLowerCase().includes("finding");
    if (isFinding) return;

    const description = nodeTypeDescriptions[nodeType];

    // Determine shape based on node type
    const isInternet = nodeType.toLowerCase() === "internet";
    const shape: "rectangle" | "hexagon" | "cloud" = isInternet
      ? "cloud"
      : "rectangle";

    if (description) {
      items.push({
        label: description.name,
        color: getNodeColor([nodeType]),
        borderColor: getNodeBorderColor([nodeType]),
        description: description.description,
        shape,
      });
    } else {
      // Format unknown node types nicely
      const formattedName = formatNodeTypeName(nodeType);
      items.push({
        label: formattedName,
        color: getNodeColor([nodeType]),
        borderColor: getNodeBorderColor([nodeType]),
        description: `${formattedName} node`,
        shape,
      });
    }
  });

  return items;
}

/**
 * Hexagon shape component for legend
 */
const HexagonShape = ({
  color,
  borderColor,
}: {
  color: string;
  borderColor: string;
}) => (
  <svg width="32" height="22" viewBox="0 0 32 22" aria-hidden="true">
    <defs>
      <filter id="legendGlow" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="1" result="coloredBlur" />
        <feMerge>
          <feMergeNode in="coloredBlur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
    <path
      d="M5 1 L27 1 L31 11 L27 21 L5 21 L1 11 Z"
      fill={color}
      fillOpacity={0.85}
      stroke={borderColor}
      strokeWidth={1.5}
      filter="url(#legendGlow)"
    />
  </svg>
);

/**
 * Pill shape component for legend
 */
const PillShape = ({
  color,
  borderColor,
}: {
  color: string;
  borderColor: string;
}) => (
  <svg width="36" height="20" viewBox="0 0 36 20" aria-hidden="true">
    <defs>
      <filter id="legendGlow2" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="1" result="coloredBlur" />
        <feMerge>
          <feMergeNode in="coloredBlur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
    <rect
      x="1"
      y="1"
      width="34"
      height="18"
      rx="9"
      ry="9"
      fill={color}
      fillOpacity={0.85}
      stroke={borderColor}
      strokeWidth={1.5}
      filter="url(#legendGlow2)"
    />
  </svg>
);

/**
 * Globe shape component for legend (used for Internet nodes)
 */
const GlobeShape = ({
  color,
  borderColor,
}: {
  color: string;
  borderColor: string;
}) => (
  <svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
    <defs>
      <filter id="legendGlow3" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="1" result="coloredBlur" />
        <feMerge>
          <feMergeNode in="coloredBlur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
    {/* Globe circle */}
    <circle
      cx="12"
      cy="12"
      r="10"
      fill={color}
      fillOpacity={0.85}
      stroke={borderColor}
      strokeWidth={1.5}
      filter="url(#legendGlow3)"
    />
    {/* Horizontal line */}
    <ellipse
      cx="12"
      cy="12"
      rx="10"
      ry="4"
      fill="none"
      stroke={borderColor}
      strokeWidth={1}
      strokeOpacity={0.6}
    />
    {/* Vertical ellipse */}
    <ellipse
      cx="12"
      cy="12"
      rx="4"
      ry="10"
      fill="none"
      stroke={borderColor}
      strokeWidth={1}
      strokeOpacity={0.6}
    />
  </svg>
);

/**
 * Edge line component for legend
 */
const EdgeLine = ({
  dashed,
  edgeColor,
}: {
  dashed: boolean;
  edgeColor: string;
}) => (
  <svg
    width="60"
    height="20"
    viewBox="0 0 60 20"
    aria-hidden="true"
    style={{ overflow: "visible" }}
  >
    {/* Line */}
    <line
      x1="4"
      y1="10"
      x2="44"
      y2="10"
      stroke={edgeColor}
      strokeWidth={3}
      strokeLinecap="round"
      strokeDasharray={dashed ? "8,6" : undefined}
    />
    {/* Arrow head */}
    <polygon points="44,5 56,10 44,15" fill={edgeColor} />
  </svg>
);

interface GraphLegendProps {
  data?: AttackPathGraphData;
}

/**
 * Legend for attack path graph node types and edge styles
 */
export const GraphLegend = ({ data }: GraphLegendProps) => {
  const { resolvedTheme } = useTheme();
  const nodeTypes = extractNodeTypes(data?.nodes);

  // Get edge color based on current theme
  const edgeColor =
    resolvedTheme === "dark" ? GRAPH_EDGE_COLOR_DARK : GRAPH_EDGE_COLOR_LIGHT;

  // Check if there are any findings in the data
  const hasFindings = nodeTypes.some((type) =>
    type.toLowerCase().includes("finding"),
  );

  const legendItems = generateLegendItems(nodeTypes, hasFindings);

  if (legendItems.length === 0) {
    return null;
  }

  return (
    <Card className="w-fit border-0">
      <CardContent className="gap-3 p-4">
        <div className="flex flex-col gap-4">
          {/* Node types section */}
          <div className="flex flex-col items-start gap-3 lg:flex-row lg:flex-wrap lg:items-center">
            <TooltipProvider>
              {legendItems.map((item) => (
                <Tooltip key={item.label}>
                  <TooltipTrigger asChild>
                    <div
                      className="flex cursor-help items-center gap-2"
                      role="img"
                      aria-label={`${item.label}: ${item.description}`}
                    >
                      {item.shape === "hexagon" ? (
                        <HexagonShape
                          color={item.color}
                          borderColor={item.borderColor}
                        />
                      ) : item.shape === "cloud" ? (
                        <GlobeShape
                          color={item.color}
                          borderColor={item.borderColor}
                        />
                      ) : (
                        <PillShape
                          color={item.color}
                          borderColor={item.borderColor}
                        />
                      )}
                      <span className="text-text-neutral-secondary text-xs">
                        {item.label}
                      </span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>{item.description}</TooltipContent>
                </Tooltip>
              ))}
            </TooltipProvider>
          </div>

          {/* Edge types section */}
          <div className="border-border-neutral-primary flex flex-col items-start gap-3 border-t pt-3 lg:flex-row lg:flex-wrap lg:items-center">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div
                    className="flex cursor-help items-center gap-2"
                    role="img"
                    aria-label="Solid line: Resource connection"
                  >
                    <EdgeLine dashed={false} edgeColor={edgeColor} />
                    <span className="text-text-neutral-secondary text-xs">
                      Resource Connection
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>
                  Connection between infrastructure resources
                </TooltipContent>
              </Tooltip>

              {hasFindings && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div
                      className="flex cursor-help items-center gap-2"
                      role="img"
                      aria-label="Dashed line: Finding connection"
                    >
                      <EdgeLine dashed={true} edgeColor={edgeColor} />
                      <span className="text-text-neutral-secondary text-xs">
                        Finding Connection
                      </span>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    Connection to a security finding
                  </TooltipContent>
                </Tooltip>
              )}
            </TooltipProvider>
          </div>

          {/* Zoom control hint */}
          <div className="border-border-neutral-primary flex items-center gap-2 border-t pt-3">
            <kbd className="bg-bg-neutral-tertiary text-text-neutral-secondary rounded px-1.5 py-0.5 text-xs font-medium">
              Ctrl
            </kbd>
            <span className="text-text-neutral-secondary text-xs">+</span>
            <span className="text-text-neutral-secondary text-xs">
              Scroll to zoom
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
