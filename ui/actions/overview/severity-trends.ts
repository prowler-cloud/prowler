"use server";

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
} = {}) => {
  // TODO: Replace with actual API call when endpoint is available
  // const headers = await getAuthHeaders({ contentType: false });
  // const url = new URL(`${apiBaseUrl}/findings/severity/time-series`);
  // Object.entries(filters).forEach(([key, value]) => {
  //   if (value) url.searchParams.append(key, String(value));
  // });
  // const response = await fetch(url.toString(), { headers });
  // return handleApiResponse(response);

  // Extract date range from filters to simulate different data based on selection
  const startDateStr = filters["filter[inserted_at__gte]"] as
    | string
    | undefined;
  const endDateStr = filters["filter[inserted_at__lte]"] as string | undefined;

  // Generate mock data based on the date range
  let mockData;

  if (startDateStr && endDateStr) {
    const startDate = new Date(startDateStr);
    const endDate = new Date(endDateStr);
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
        type: "severity-time-series",
        id: dateStr,
        date: `${dateStr}T00:00:00Z`,
        informational: Math.max(0, 380 + dayOffset * 15),
        low: Math.max(0, 720 + dayOffset * 20),
        medium: Math.max(0, 550 + dayOffset * 10),
        high: Math.max(0, 1000 - dayOffset * 5),
        critical: Math.max(0, 1200 - dayOffset * 30),
        muted: Math.max(0, 500 - dayOffset * 25),
      });
    }

    mockData = {
      data: dataPoints,
      links: {
        self: `https://api.prowler.com/api/v1/findings/severity/time-series?start=${startDateStr}&end=${endDateStr}`,
      },
      meta: {
        date_range: `${startDateStr} to ${endDateStr}`,
        days: daysDiff,
        granularity: "daily",
        timezone: "UTC",
      },
    };
  } else {
    // Default 5-day data if no date range provided
    mockData = {
      data: [
        {
          type: "severity-time-series",
          id: "2025-10-26",
          date: "2025-10-26T00:00:00Z",
          informational: 420,
          low: 950,
          medium: 720,
          high: 1150,
          critical: 1350,
          muted: 600,
        },
        {
          type: "severity-time-series",
          id: "2025-10-27",
          date: "2025-10-27T00:00:00Z",
          informational: 450,
          low: 1100,
          medium: 850,
          high: 1300,
          critical: 1500,
          muted: 700,
        },
        {
          type: "severity-time-series",
          id: "2025-10-28",
          date: "2025-10-28T00:00:00Z",
          informational: 400,
          low: 850,
          medium: 650,
          high: 1200,
          critical: 2000,
          muted: 750,
        },
        {
          type: "severity-time-series",
          id: "2025-10-29",
          date: "2025-10-29T00:00:00Z",
          informational: 380,
          low: 720,
          medium: 550,
          high: 1000,
          critical: 1200,
          muted: 500,
        },
        {
          type: "severity-time-series",
          id: "2025-11-10",
          date: "2025-11-10T00:00:00Z",
          informational: 500,
          low: 750,
          medium: 350,
          high: 1000,
          critical: 550,
          muted: 100,
        },
      ],
      links: {
        self: "https://api.prowler.com/api/v1/findings/severity/time-series?range=5D",
      },
      meta: {
        time_range: "5D",
        granularity: "daily",
        timezone: "UTC",
      },
    };
  }

  return mockData;
};

export const getSeverityTrendsByTimeRange = async ({
  timeRange,
  filters = {},
}: {
  timeRange: TimeRange;
  filters?: Record<string, string | string[] | undefined>;
}) => {
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

  // Format dates as ISO strings for API
  const startDateStr = startDate.toISOString().split("T")[0];
  const endDateStr = endDate.toISOString().split("T")[0];

  // Add date filters to the request
  const dateFilters = {
    ...filters,
    "filter[inserted_at__gte]": startDateStr,
    "filter[inserted_at__lte]": endDateStr,
  };

  return getFindingsSeverityTrends({ filters: dateFilters });
};

export { getFindingsSeverityTrends };
