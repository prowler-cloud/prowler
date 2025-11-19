/**
 * Color constants for attack path graph visualization
 * Using semantic color palette for design system consistency
 */

export const GRAPH_NODE_COLORS = {
  prowlerFinding: "#f69000", // AWS orange
  awsAccount: "#60a5fa", // Azure blue
  ec2Instance: "#ef4444", // GCP red
  s3Bucket: "#4f46e5", // Kubernetes indigo
  iamRole: "#e5e7eb", // GitHub neutral
  default: "#4ade80", // M365 green
} as const;

export const GRAPH_EDGE_COLOR = "#a1a1a1"; // neutral-tertiary
export const GRAPH_SELECTION_COLOR = "#fbbf24"; // warning orange
export const GRAPH_BORDER_COLOR = "#d4d4d8"; // border-neutral-tertiary

export const getNodeColor = (labels: string[]): string => {
  if (labels.includes("ProwlerFinding"))
    return GRAPH_NODE_COLORS.prowlerFinding;
  if (labels.includes("AWSAccount")) return GRAPH_NODE_COLORS.awsAccount;
  if (labels.includes("EC2Instance")) return GRAPH_NODE_COLORS.ec2Instance;
  if (labels.includes("S3Bucket")) return GRAPH_NODE_COLORS.s3Bucket;
  if (labels.includes("IAMRole")) return GRAPH_NODE_COLORS.iamRole;
  return GRAPH_NODE_COLORS.default;
};
