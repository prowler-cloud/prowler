import { LineDataPoint } from "@/components/graphs/types";

// API Response Types (what comes from the backend)
export interface FindingsSeverityOverTimeAttributes {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  muted: number;
}

export interface FindingsSeverityOverTimeItem {
  type: "findings-severity-over-time";
  id: string;
  attributes: FindingsSeverityOverTimeAttributes;
}

export interface FindingsSeverityOverTimeMeta {
  version: string;
}

export interface FindingsSeverityOverTimeResponse {
  data: FindingsSeverityOverTimeItem[];
  meta: FindingsSeverityOverTimeMeta;
}

// Adapted Types (what the UI components expect)
export interface AdaptedSeverityTrendsResponse {
  data: LineDataPoint[];
  meta: FindingsSeverityOverTimeMeta;
}

/**
 * Adapts the API findings severity over time response to the format expected by LineChart.
 * Transforms API response with nested attributes into flat LineDataPoint objects.
 *
 * @param response - The raw API response from /overviews/findings_severity_over_time
 * @returns Adapted response with LineDataPoint array ready for the chart
 */
export function adaptSeverityTrendsResponse(
  response: FindingsSeverityOverTimeResponse,
): AdaptedSeverityTrendsResponse {
  const adaptedData: LineDataPoint[] = response.data.map(
    ({
      attributes: { date, informational, low, medium, high, critical, muted },
    }) => ({
      date,
      informational,
      low,
      medium,
      high,
      critical,
      muted,
    }),
  );

  return {
    data: adaptedData,
    meta: response.meta,
  };
}
