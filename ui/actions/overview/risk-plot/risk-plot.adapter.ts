import { getProviderDisplayName } from "@/types/providers";

import type {
  ProviderRiskData,
  RiskPlotDataResponse,
  RiskPlotPoint,
} from "./types/risk-plot.types";

/**
 * Calculates percentage with proper rounding.
 */
function calculatePercentage(value: number, total: number): number {
  if (total === 0) return 0;
  return Math.round((value / total) * 100);
}

/**
 * Adapts raw provider risk data to the format expected by RiskPlotClient.
 *
 * @param providersRiskData - Array of risk data per provider from API
 * @returns Formatted data for the Risk Plot scatter chart
 */
export function adaptToRiskPlotData(
  providersRiskData: ProviderRiskData[],
): RiskPlotDataResponse {
  const points: RiskPlotPoint[] = [];
  const providersWithoutData: RiskPlotDataResponse["providersWithoutData"] = [];

  for (const providerData of providersRiskData) {
    // Skip providers without ThreatScore data (no completed scans)
    if (providerData.overallScore === null) {
      providersWithoutData.push({
        id: providerData.providerId,
        name: providerData.providerName,
        type: providerData.providerType,
      });
      continue;
    }

    // Convert provider type to display name (aws -> AWS, gcp -> Google, etc.)
    const providerDisplayName = getProviderDisplayName(
      providerData.providerType,
    );

    // Build severity data for the horizontal bar chart with percentages
    let severityData;
    let totalFailedFindings = 0;

    if (providerData.severity) {
      const { critical, high, medium, low, informational } =
        providerData.severity;
      totalFailedFindings = critical + high + medium + low + informational;

      severityData = [
        {
          name: "Critical",
          value: critical,
          percentage: calculatePercentage(critical, totalFailedFindings),
        },
        {
          name: "High",
          value: high,
          percentage: calculatePercentage(high, totalFailedFindings),
        },
        {
          name: "Medium",
          value: medium,
          percentage: calculatePercentage(medium, totalFailedFindings),
        },
        {
          name: "Low",
          value: low,
          percentage: calculatePercentage(low, totalFailedFindings),
        },
        {
          name: "Info",
          value: informational,
          percentage: calculatePercentage(informational, totalFailedFindings),
        },
      ];
    }

    points.push({
      x: providerData.overallScore ?? 0,
      y: totalFailedFindings,
      provider: providerDisplayName,
      name: providerData.providerName,
      providerId: providerData.providerId,
      severityData,
    });
  }

  return { points, providersWithoutData };
}
