import { LineDataPoint } from "@/components/graphs/types";

import {
  AdaptedSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "./types";

export type { AdaptedSeverityTrendsResponse, FindingsSeverityOverTimeResponse };

/**
 * Adapts the API findings severity over time response to the format expected by LineChart.
 * Transforms API response with nested attributes into flat LineDataPoint objects.
 *
 * @param response - The raw API response from /overviews/findings_severity/timeseries
 * @returns Adapted response with LineDataPoint array ready for the chart
 */
export function adaptSeverityTrendsResponse(
  response: FindingsSeverityOverTimeResponse,
): AdaptedSeverityTrendsResponse {
  const adaptedData: LineDataPoint[] = response.data.map(
    ({
      id,
      attributes: {
        informational,
        low,
        medium,
        high,
        critical,
        muted,
        scan_ids,
      },
    }) => ({
      date: id,
      informational,
      low,
      medium,
      high,
      critical,
      muted,
      scan_ids,
    }),
  );

  return {
    data: adaptedData,
    meta: response.meta,
  };
}
