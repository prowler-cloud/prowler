"use server";

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
} = {}): Promise<AdaptedSeverityTrendsResponse> => {
  // TODO: Replace with actual API call when endpoint is available
  // const headers = await getAuthHeaders({ contentType: false });
  // const url = new URL(`${apiBaseUrl}/findings/severity-over-time`);
  // Object.entries(filters).forEach(([key, value]) => {
  //   if (value) url.searchParams.append(key, String(value));
  // });
  // const response = await fetch(url.toString(), { headers });
  // const apiResponse = await handleApiResponse(response);
  // return adaptSeverityTrendsResponse(apiResponse);

  // Extract date range from filters
  const dateFrom = filters["date_from"] as string | undefined;
  const dateTo = filters["date_to"] as string | undefined;

  // Generate mock data based on the date range
  let mockApiResponse: FindingsSeverityOverTimeResponse;

  // If date_to is not specified, use today
  const endDate = dateTo ? new Date(dateTo) : new Date();

  if (dateFrom) {
    const startDate = new Date(dateFrom);
    const daysDiff = Math.ceil(
      (endDate.getTime() - startDate.getTime()) / (24 * 60 * 60 * 1000),
    );

    // Generate data points for each day in the range
    const dataPoints = [];
    for (let i = 0; i <= daysDiff; i++) {
      const currentDate = new Date(startDate);
      currentDate.setDate(currentDate.getDate() + i);
      const dateStr = currentDate.toISOString().split("T")[0];

      // Vary the data based on the day for visual difference
      const dayOffset = i;
      dataPoints.push({
        type: "findings-severity-over-time" as const,
        id: dateStr,
        attributes: {
          date: dateStr,
          critical: Math.max(0, 1200 - dayOffset * 30),
          high: Math.max(0, 1000 - dayOffset * 5),
          medium: Math.max(0, 550 + dayOffset * 10),
          low: Math.max(0, 720 + dayOffset * 20),
          informational: Math.max(0, 380 + dayOffset * 15),
          muted: Math.max(0, 500 - dayOffset * 25),
        },
      });
    }

    mockApiResponse = {
      data: dataPoints,
      meta: {
        version: "v1",
      },
    };
  } else {
    // Default 5-day data if no date range provided
    mockApiResponse = {
      data: [
        {
          type: "findings-severity-over-time",
          id: "2025-09-02",
          attributes: {
            date: "2025-09-02",
            critical: 1500,
            high: 1300,
            medium: 850,
            low: 1100,
            informational: 450,
            muted: 700,
          },
        },
        {
          type: "findings-severity-over-time",
          id: "2025-09-03",
          attributes: {
            date: "2025-09-03",
            critical: 550,
            high: 1000,
            medium: 350,
            low: 750,
            informational: 500,
            muted: 100,
          },
        },
        {
          type: "findings-severity-over-time",
          id: "2025-09-04",
          attributes: {
            date: "2025-09-04",
            critical: 1350,
            high: 1150,
            medium: 720,
            low: 950,
            informational: 420,
            muted: 600,
          },
        },
        {
          type: "findings-severity-over-time",
          id: "2025-09-05",
          attributes: {
            date: "2025-09-05",
            critical: 1200,
            high: 1000,
            medium: 550,
            low: 720,
            informational: 380,
            muted: 500,
          },
        },
        {
          type: "findings-severity-over-time",
          id: "2025-09-06",
          attributes: {
            date: "2025-09-06",
            critical: 2000,
            high: 1200,
            medium: 650,
            low: 850,
            informational: 400,
            muted: 750,
          },
        },
      ],
      meta: {
        version: "v1",
      },
    };
  }

  // Use the adapter to transform API response to UI format
  return adaptSeverityTrendsResponse(mockApiResponse);
};

export const getSeverityTrendsByTimeRange = async ({
  timeRange,
  filters = {},
}: {
  timeRange: TimeRange;
  filters?: Record<string, string | string[] | undefined>;
}): Promise<AdaptedSeverityTrendsResponse> => {
  // Find the days value from TIME_RANGE_OPTIONS
  const timeRangeConfig = Object.values(TIME_RANGE_OPTIONS).find(
    (option) => option.value === timeRange,
  );

  if (!timeRangeConfig) {
    throw new Error(`Invalid time range: ${timeRange}`);
  }

  const endDate = new Date();
  const startDate = new Date(
    endDate.getTime() - timeRangeConfig.days * 24 * 60 * 60 * 1000,
  );

  // Format dates as ISO strings for API (date_from, date_to is optional)
  const dateFrom = startDate.toISOString().split("T")[0];

  // Add date filters to the request
  const dateFilters = {
    ...filters,
    date_from: dateFrom,
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
