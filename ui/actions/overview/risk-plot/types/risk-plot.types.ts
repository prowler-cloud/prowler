// Risk Plot Types
// Data structures for the Risk Plot scatter chart

import type { BarDataPoint } from "@/components/graphs/types";

/**
 * Represents a single point in the Risk Plot scatter chart.
 * Each point represents a provider/account with its risk metrics.
 */
export interface RiskPlotPoint {
  /** ThreatScore (0-100 scale, higher = better) */
  x: number;
  /** Total failed findings count */
  y: number;
  /** Provider type display name (AWS, Azure, Google, etc.) */
  provider: string;
  /** Provider alias or UID (account identifier) */
  name: string;
  /** Provider ID for filtering/navigation */
  providerId: string;
  /** Severity breakdown for the horizontal bar chart */
  severityData?: BarDataPoint[];
}

/**
 * Raw data from the API combined for a single provider.
 * Used internally before transformation to RiskPlotPoint.
 */
export interface ProviderRiskData {
  providerId: string;
  providerType: string;
  providerName: string;
  /** ThreatScore overall_score (0-100 scale) */
  overallScore: number | null;
  /** Failed findings from ThreatScore snapshot */
  failedFindings: number;
  /** Severity breakdown */
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  } | null;
}

/**
 * Response structure for risk plot data fetching.
 */
export interface RiskPlotDataResponse {
  points: RiskPlotPoint[];
  /** Providers that have no data or no completed scans */
  providersWithoutData: Array<{
    id: string;
    name: string;
    type: string;
  }>;
}
