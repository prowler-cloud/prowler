import type { RadarDataPoint } from "@/components/graphs/types";

import { CategoryOverview, CategoryOverviewResponse } from "./types";

// Category IDs from the API
const CATEGORY_IDS = {
  E3: "e3",
  E5: "e5",
  ENCRYPTION: "encryption",
  FORENSICS_READY: "forensics-ready",
  IAM: "iam",
  INTERNET_EXPOSED: "internet-exposed",
  LOGGING: "logging",
  NETWORK: "network",
  PUBLICLY_ACCESSIBLE: "publicly-accessible",
  SECRETS: "secrets",
  STORAGE: "storage",
  THREAT_DETECTION: "threat-detection",
  TRUSTBOUNDARIES: "trustboundaries",
  UNUSED: "unused",
} as const;

export type CategoryId = (typeof CATEGORY_IDS)[keyof typeof CATEGORY_IDS];

// Human-readable labels for category IDs
const CATEGORY_LABELS: Record<string, string> = {
  [CATEGORY_IDS.E3]: "E3",
  [CATEGORY_IDS.E5]: "E5",
  [CATEGORY_IDS.ENCRYPTION]: "Encryption",
  [CATEGORY_IDS.FORENSICS_READY]: "Forensics Ready",
  [CATEGORY_IDS.IAM]: "IAM",
  [CATEGORY_IDS.INTERNET_EXPOSED]: "Internet Exposed",
  [CATEGORY_IDS.LOGGING]: "Logging",
  [CATEGORY_IDS.NETWORK]: "Network",
  [CATEGORY_IDS.PUBLICLY_ACCESSIBLE]: "Publicly Accessible",
  [CATEGORY_IDS.SECRETS]: "Secrets",
  [CATEGORY_IDS.STORAGE]: "Storage",
  [CATEGORY_IDS.THREAT_DETECTION]: "Threat Detection",
  [CATEGORY_IDS.TRUSTBOUNDARIES]: "Trust Boundaries",
  [CATEGORY_IDS.UNUSED]: "Unused",
};

/**
 * Converts a category ID to a human-readable label.
 * Falls back to capitalizing the ID if not found in the mapping.
 */
function getCategoryLabel(id: string): string {
  if (CATEGORY_LABELS[id]) {
    return CATEGORY_LABELS[id];
  }
  // Fallback: capitalize and replace hyphens with spaces
  return id
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

/**
 * Maps a single category overview item to a RadarDataPoint.
 */
function mapCategoryToRadarPoint(item: CategoryOverview): RadarDataPoint {
  const { id, attributes } = item;
  const { failed_findings, new_failed_findings, severity } = attributes;

  return {
    category: getCategoryLabel(id),
    value: failed_findings,
    change: new_failed_findings,
    severityData: [
      { name: "Critical", value: severity.critical },
      { name: "High", value: severity.high },
      { name: "Medium", value: severity.medium },
      { name: "Low", value: severity.low },
      { name: "Info", value: severity.informational },
    ],
  };
}

/**
 * Adapts the category overview API response to RadarDataPoint[] format.
 * Filters out categories with no failed findings.
 *
 * @param response - The category overview API response
 * @returns An array of RadarDataPoint objects for the radar chart
 */
export function adaptCategoryOverviewToRadarData(
  response: CategoryOverviewResponse | undefined,
): RadarDataPoint[] {
  if (!response?.data || response.data.length === 0) {
    return [];
  }

  // Map all categories to radar points, filtering out those with no failed findings
  return response.data
    .filter((item) => item.attributes.failed_findings > 0)
    .map(mapCategoryToRadarPoint)
    .sort((a, b) => b.value - a.value); // Sort by failed findings descending
}
