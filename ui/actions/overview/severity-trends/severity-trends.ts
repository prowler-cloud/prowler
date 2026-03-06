"use server";

import {
  getDateFromForTimeRange,
  type TimeRange,
} from "@/app/(prowler)/_overview/severity-over-time/_constants/time-range.constants";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { appendSanitizedProviderTypeFilters } from "@/lib/provider-filters";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { adaptSeverityTrendsResponse } from "./severity-trends.adapter";
import {
  AdaptedSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "./types";

export type SeverityTrendsResult =
  | { status: "success"; data: AdaptedSeverityTrendsResponse }
  | { status: "empty" }
  | { status: "error" };

const getFindingsSeverityTrends = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<SeverityTrendsResult> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/findings_severity/timeseries`);

  appendSanitizedProviderTypeFilters(url, filters);

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    const apiResponse: FindingsSeverityOverTimeResponse | undefined =
      await handleApiResponse(response);

    if (!apiResponse?.data || !Array.isArray(apiResponse.data)) {
      return { status: "empty" };
    }

    if (apiResponse.data.length === 0) {
      return { status: "empty" };
    }

    return {
      status: "success",
      data: adaptSeverityTrendsResponse(apiResponse),
    };
  } catch (error) {
    console.error("Error fetching findings severity trends:", error);
    return { status: "error" };
  }
};

export const getSeverityTrendsByTimeRange = async ({
  timeRange,
  filters = {},
}: {
  timeRange: TimeRange;
  filters?: Record<string, string | string[] | undefined>;
}): Promise<SeverityTrendsResult> => {
  const dateFilters = {
    ...filters,
    "filter[date_from]": getDateFromForTimeRange(timeRange),
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
