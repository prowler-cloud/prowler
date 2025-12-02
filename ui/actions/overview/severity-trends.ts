"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import {
  AdaptedSeverityTrendsResponse,
  adaptSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "./severity-trends.adapter";

const TIME_RANGE_OPTIONS = {
  ONE_DAY: { value: "1D", days: 1 },
  FIVE_DAYS: { value: "5D", days: 5 },
  ONE_WEEK: { value: "1W", days: 7 },
  ONE_MONTH: { value: "1M", days: 30 },
} as const;

type TimeRange =
  (typeof TIME_RANGE_OPTIONS)[keyof typeof TIME_RANGE_OPTIONS]["value"];

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
  const timeRangeConfig = Object.values(TIME_RANGE_OPTIONS).find(
    (option) => option.value === timeRange,
  );

  if (!timeRangeConfig) {
    console.error(`Invalid time range: ${timeRange}`);
    return undefined;
  }

  const endDate = new Date();
  const startDate = new Date(
    endDate.getTime() - timeRangeConfig.days * 24 * 60 * 60 * 1000,
  );

  const dateFrom = startDate.toISOString().split("T")[0];

  const dateFilters = {
    ...filters,
    date_from: dateFrom,
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
