"use server";

import {
  AdaptedSeverityTrendsResponse,
  adaptSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "./severity-trends.adapter";

const TIME_RANGE_OPTIONS = {
  FIVE_DAYS: { value: "5D", days: 5 },
  ONE_WEEK: { value: "1W", days: 7 },
  ONE_MONTH: { value: "1M", days: 30 },
} as const;

type TimeRange =
  (typeof TIME_RANGE_OPTIONS)[keyof typeof TIME_RANGE_OPTIONS]["value"];

/**
 * Generates mock severity data for a given number of days
 */
const generateMockData = (
  days: number,
): FindingsSeverityOverTimeResponse["data"] => {
  const dataPoints = [];
  const today = new Date();

  for (let i = days - 1; i >= 0; i--) {
    const currentDate = new Date(today);
    currentDate.setDate(currentDate.getDate() - i);
    const dateStr = currentDate.toISOString().split("T")[0];

    // Generate varied data for visual difference
    const dayIndex = days - 1 - i;
    dataPoints.push({
      type: "findings-severity-over-time" as const,
      id: dateStr,
      attributes: {
        date: dateStr,
        critical: Math.max(100, 1500 - dayIndex * 30 + Math.floor(Math.random() * 200)),
        high: Math.max(200, 1300 - dayIndex * 20 + Math.floor(Math.random() * 150)),
        medium: Math.max(150, 850 + dayIndex * 10 + Math.floor(Math.random() * 100)),
        low: Math.max(300, 1100 + dayIndex * 15 + Math.floor(Math.random() * 80)),
        informational: Math.max(100, 450 + dayIndex * 5 + Math.floor(Math.random() * 50)),
        muted: Math.max(50, 700 - dayIndex * 10 + Math.floor(Math.random() * 60)),
      },
    });
  }

  return dataPoints;
};

const getFindingsSeverityTrends = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<AdaptedSeverityTrendsResponse | undefined> => {
  // TODO: Replace with actual API call when endpoint is available
  // const headers = await getAuthHeaders({ contentType: false });
  // const url = new URL(`${apiBaseUrl}/overviews/findings_severity_over_time`);
  // Object.entries(filters).forEach(([key, value]) => {
  //   if (value !== undefined) {
  //     url.searchParams.append(key, String(value));
  //   }
  // });
  // try {
  //   const response = await fetch(url.toString(), { headers });
  //   const apiResponse = await handleApiResponse(response);
  //   if (!apiResponse) return undefined;
  //   return adaptSeverityTrendsResponse(apiResponse);
  // } catch (error) {
  //   console.error("Error fetching findings severity trends:", error);
  //   return undefined;
  // }

  // Extract days from filters to generate appropriate mock data
  const days = Number(filters["days"]) || 5;

  const mockApiResponse: FindingsSeverityOverTimeResponse = {
    data: generateMockData(days),
    meta: {
      version: "v1",
    },
  };

  return adaptSeverityTrendsResponse(mockApiResponse);
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
    console.error("Invalid time range provided");
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
    days: String(timeRangeConfig.days),
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
