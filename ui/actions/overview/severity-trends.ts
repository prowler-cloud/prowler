"use server";

import { getFindingsSeverityTrends } from "./overview";

const TIME_RANGE_OPTIONS = {
  ONE_DAY: { value: "1D", days: 1 },
  FIVE_DAYS: { value: "5D", days: 5 },
  ONE_WEEK: { value: "1W", days: 7 },
  ONE_MONTH: { value: "1M", days: 30 },
} as const;

type TimeRange =
  (typeof TIME_RANGE_OPTIONS)[keyof typeof TIME_RANGE_OPTIONS]["value"];

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
