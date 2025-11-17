/**
 * Color constants for attack path graph visualization
 * Using Tailwind color palette values for semantic consistency
 */

export const GRAPH_NODE_COLORS = {
  prowlerFinding: "#f97316", // orange-500
  awsAccount: "#3b82f6", // blue-500
  ec2Instance: "#06b6d4", // cyan-500
  s3Bucket: "#8b5cf6", // purple-500
  iamRole: "#ec4899", // pink-500
  default: "#10b981", // green-500
} as const;

export const GRAPH_EDGE_COLOR = "#666"; // neutral-600
export const GRAPH_SELECTION_COLOR = "#fbbf24"; // amber-400
export const GRAPH_BORDER_COLOR = "#e5e7eb"; // gray-200

export const getNodeColor = (labels: string[]): string => {
  if (labels.includes("ProwlerFinding"))
    return GRAPH_NODE_COLORS.prowlerFinding;
  if (labels.includes("AWSAccount")) return GRAPH_NODE_COLORS.awsAccount;
  if (labels.includes("EC2Instance")) return GRAPH_NODE_COLORS.ec2Instance;
  if (labels.includes("S3Bucket")) return GRAPH_NODE_COLORS.s3Bucket;
  if (labels.includes("IAMRole")) return GRAPH_NODE_COLORS.iamRole;
  return GRAPH_NODE_COLORS.default;
};
