"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import {
  AdaptedSeverityTrendsResponse,
  adaptSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "./severity-trends.adapter";

const TIME_RANGE_VALUES = {
  FIVE_DAYS: "5D",
  ONE_WEEK: "1W",
  ONE_MONTH: "1M",
} as const;

type TimeRange = (typeof TIME_RANGE_VALUES)[keyof typeof TIME_RANGE_VALUES];

const TIME_RANGE_DAYS: Record<TimeRange, number> = {
  "5D": 5,
  "1W": 7,
  "1M": 30,
};

const getFindingsSeverityTrends = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<AdaptedSeverityTrendsResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  const url = new URL(`${apiBaseUrl}/overviews/findings_severity_over_time`);

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers,
    });

    const apiResponse: FindingsSeverityOverTimeResponse | undefined =
      await handleApiResponse(response);

    if (!apiResponse) {
      return undefined;
    }

    return adaptSeverityTrendsResponse(apiResponse);
  } catch (error) {
    console.error("Error fetching findings severity trends:", error);
    return undefined;
  }
};

export const getSeverityTrendsByTimeRange = async ({
  timeRange,
  filters = {},
}: {
  timeRange: TimeRange;
  filters?: Record<string, string | string[] | undefined>;
}): Promise<AdaptedSeverityTrendsResponse | undefined> => {
  const days = TIME_RANGE_DAYS[timeRange];

  if (!days) {
    console.error("Invalid time range provided");
    return undefined;
  }

  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);

  const dateFrom = startDate.toISOString().split("T")[0];

  const dateFilters = {
    ...filters,
    date_from: dateFrom,
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
