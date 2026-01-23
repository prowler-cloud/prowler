/**
 * Color constants for attack path graph visualization
 * Colors chosen to work well in both light and dark themes
 */

/**
 * Node fill colors - darker versions of design system severity colors
 * Darkened to ensure white text has proper contrast (WCAG AA)
 */
export const GRAPH_NODE_COLORS = {
  // Finding severities - darkened versions for white text readability
  critical: "#cc0055", // Darker pink (from #ff006a)
  high: "#c45a3a", // Darker coral (from #f77852)
  medium: "#b8860b", // Dark goldenrod (from #fec94d)
  low: "#8b9a3e", // Olive/dark yellow-green (from #fdfbd4)
  info: "#2563eb", // Darker blue (from #3c8dff)
  // Node types
  prowlerFinding: "#ea580c",
  awsAccount: "#f59e0b", // Amber 500 - AWS orange
  attackPattern: "#16a34a",
  summary: "#16a34a",
  // Infrastructure
  ec2Instance: "#0891b2", // Cyan 600
  s3Bucket: "#0284c7", // Sky 600
  iamRole: "#7c3aed", // Violet 600
  iamPolicy: "#7c3aed",
  lambdaFunction: "#d97706", // Amber 600
  securityGroup: "#0891b2",
  default: "#0891b2",
} as const;

/**
 * Node border colors - using original design system colors as borders (lighter than fill)
 */
export const GRAPH_NODE_BORDER_COLORS = {
  critical: "#ff006a", // Original --bg-data-critical
  high: "#f77852", // Original --bg-data-high
  medium: "#fec94d", // Original --bg-data-medium
  low: "#c4d4a0", // Lighter olive
  info: "#3c8dff", // Original --bg-data-info
  prowlerFinding: "#fb923c",
  awsAccount: "#fbbf24", // Amber 400
  attackPattern: "#4ade80",
  summary: "#4ade80",
  ec2Instance: "#22d3ee", // Cyan 400
  s3Bucket: "#38bdf8", // Sky 400
  iamRole: "#a78bfa", // Violet 400
  iamPolicy: "#a78bfa",
  lambdaFunction: "#fbbf24",
  securityGroup: "#22d3ee",
  default: "#22d3ee",
} as const;

// Edge colors per theme
export const GRAPH_EDGE_COLOR_DARK = "#ffffff"; // White for dark theme
export const GRAPH_EDGE_COLOR_LIGHT = "#1e293b"; // Slate 800 for light theme
export const GRAPH_EDGE_HIGHLIGHT_COLOR = "#f97316"; // Orange 500 (on hover)
export const GRAPH_EDGE_GLOW_COLOR = "#fb923c";
export const GRAPH_SELECTION_COLOR = "#ffffff";
export const GRAPH_BORDER_COLOR = "#374151";
export const GRAPH_ALERT_BORDER_COLOR = "#ef4444"; // Red 500 - for resources with findings

/**
 * Get node fill color based on labels and properties
 */
export const getNodeColor = (
  labels: string[],
  properties?: Record<string, unknown>,
): string => {
  const isFinding = labels.some((l) => l.toLowerCase().includes("finding"));
  if (isFinding && properties?.severity) {
    const severity = String(properties.severity).toLowerCase();
    if (severity === "critical") return GRAPH_NODE_COLORS.critical;
    if (severity === "high") return GRAPH_NODE_COLORS.high;
    if (severity === "medium") return GRAPH_NODE_COLORS.medium;
    if (severity === "low") return GRAPH_NODE_COLORS.low;
    if (severity === "informational" || severity === "info")
      return GRAPH_NODE_COLORS.info;
    return GRAPH_NODE_COLORS.prowlerFinding;
  }

  if (labels.some((l) => l.toLowerCase().includes("attackpattern")))
    return GRAPH_NODE_COLORS.attackPattern;
  if (labels.includes("AWSAccount")) return GRAPH_NODE_COLORS.awsAccount;
  if (labels.includes("EC2Instance")) return GRAPH_NODE_COLORS.ec2Instance;
  if (labels.includes("S3Bucket")) return GRAPH_NODE_COLORS.s3Bucket;
  if (labels.includes("IAMRole")) return GRAPH_NODE_COLORS.iamRole;
  if (labels.includes("IAMPolicy")) return GRAPH_NODE_COLORS.iamPolicy;
  if (labels.includes("LambdaFunction"))
    return GRAPH_NODE_COLORS.lambdaFunction;
  if (labels.includes("SecurityGroup")) return GRAPH_NODE_COLORS.securityGroup;

  return GRAPH_NODE_COLORS.default;
};

/**
 * Get node border color based on labels and properties
 */
export const getNodeBorderColor = (
  labels: string[],
  properties?: Record<string, unknown>,
): string => {
  const isFinding = labels.some((l) => l.toLowerCase().includes("finding"));
  if (isFinding && properties?.severity) {
    const severity = String(properties.severity).toLowerCase();
    if (severity === "critical") return GRAPH_NODE_BORDER_COLORS.critical;
    if (severity === "high") return GRAPH_NODE_BORDER_COLORS.high;
    if (severity === "medium") return GRAPH_NODE_BORDER_COLORS.medium;
    if (severity === "low") return GRAPH_NODE_BORDER_COLORS.low;
    if (severity === "informational" || severity === "info")
      return GRAPH_NODE_BORDER_COLORS.info;
    return GRAPH_NODE_BORDER_COLORS.prowlerFinding;
  }

  if (labels.some((l) => l.toLowerCase().includes("attackpattern")))
    return GRAPH_NODE_BORDER_COLORS.attackPattern;
  if (labels.includes("AWSAccount")) return GRAPH_NODE_BORDER_COLORS.awsAccount;
  if (labels.includes("EC2Instance"))
    return GRAPH_NODE_BORDER_COLORS.ec2Instance;
  if (labels.includes("S3Bucket")) return GRAPH_NODE_BORDER_COLORS.s3Bucket;
  if (labels.includes("IAMRole")) return GRAPH_NODE_BORDER_COLORS.iamRole;
  if (labels.includes("IAMPolicy")) return GRAPH_NODE_BORDER_COLORS.iamPolicy;
  if (labels.includes("LambdaFunction"))
    return GRAPH_NODE_BORDER_COLORS.lambdaFunction;
  if (labels.includes("SecurityGroup"))
    return GRAPH_NODE_BORDER_COLORS.securityGroup;

  return GRAPH_NODE_BORDER_COLORS.default;
};

/**
 * Check if a background color is light (for determining text color)
 */
export const isLightBackground = (backgroundColor: string): boolean => {
  const hex = backgroundColor.replace("#", "");
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.5;
};
