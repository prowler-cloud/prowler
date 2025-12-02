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
export interface SeverityDataPoint {
  type: string;
  id: string;
  date: string;
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
  muted?: number;
}

export interface AdaptedSeverityTrendsResponse {
  data: SeverityDataPoint[];
  meta: FindingsSeverityOverTimeMeta;
}

/**
 * Adapts the API findings severity over time response to the format expected by UI components.
 * Main transformation: Flattens `attributes` into the data point object
 *
 * @param response - The raw API response from /findings/severity-over-time
 * @returns Adapted response with flattened data points
 */
export function adaptSeverityTrendsResponse(
  response: FindingsSeverityOverTimeResponse,
): AdaptedSeverityTrendsResponse {
  const adaptedData: SeverityDataPoint[] = response.data.map((item) => ({
    type: item.type,
    id: item.id,
    date: item.attributes.date,
    informational: item.attributes.informational,
    low: item.attributes.low,
    medium: item.attributes.medium,
    high: item.attributes.high,
    critical: item.attributes.critical,
    muted: item.attributes.muted,
  }));

  return {
    data: adaptedData,
    meta: response.meta,
  };
}
