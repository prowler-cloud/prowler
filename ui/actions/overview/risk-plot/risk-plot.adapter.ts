import { getProviderDisplayName } from "@/types/providers";

import type {
  ProviderRiskData,
  RiskPlotDataResponse,
  RiskPlotPoint,
} from "./types/risk-plot.types";

/**
 * Converts ThreatScore (0-100) to Risk Score (0-10).
 * Both scales use "higher = better" convention.
 */
function convertToRiskScore(overallScore: number | null): number {
  if (overallScore === null) return 0;
  // ThreatScore is 0-100, we need 0-10
  // Higher = better in both scales
  return Math.round((overallScore / 10) * 10) / 10;
}

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
    if (providerData.severity) {
      const { critical, high, medium, low, informational } =
        providerData.severity;
      const total = critical + high + medium + low + informational;

      severityData = [
        {
          name: "Critical",
          value: critical,
          percentage: calculatePercentage(critical, total),
        },
        {
          name: "High",
          value: high,
          percentage: calculatePercentage(high, total),
        },
        {
          name: "Medium",
          value: medium,
          percentage: calculatePercentage(medium, total),
        },
        {
          name: "Low",
          value: low,
          percentage: calculatePercentage(low, total),
        },
        {
          name: "Info",
          value: informational,
          percentage: calculatePercentage(informational, total),
        },
      ];
    }

    points.push({
      x: convertToRiskScore(providerData.overallScore),
      y: providerData.failedFindings,
      provider: providerDisplayName,
      name: providerData.providerName,
      providerId: providerData.providerId,
      severityData,
    });
  }

  return { points, providersWithoutData };
}
