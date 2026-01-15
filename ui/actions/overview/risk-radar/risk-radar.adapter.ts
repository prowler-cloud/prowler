import type { RadarDataPoint } from "@/components/graphs/types";
import { getCategoryLabel } from "@/lib/categories";

import { CategoryOverview, CategoryOverviewResponse } from "./types";

/**
 * Calculates the percentage of new failed findings relative to total failed findings.
 */
function calculateChangePercentage(
  newFailedFindings: number,
  failedFindings: number,
): number {
  if (failedFindings === 0) return 0;
  return Math.round((newFailedFindings / failedFindings) * 100);
}

/**
 * Maps a single category overview item to a RadarDataPoint.
 */
function mapCategoryToRadarPoint(item: CategoryOverview): RadarDataPoint {
  const { id, attributes } = item;
  const { failed_findings, new_failed_findings, severity } = attributes;

  return {
    category: getCategoryLabel(id),
    categoryId: id,
    value: failed_findings,
    change: calculateChangePercentage(new_failed_findings, failed_findings),
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
