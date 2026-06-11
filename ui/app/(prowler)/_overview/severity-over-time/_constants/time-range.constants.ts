export const TIME_RANGE_OPTIONS = {
  FIVE_DAYS: "5D",
  ONE_WEEK: "1W",
  ONE_MONTH: "1M",
} as const;

export type TimeRange =
  (typeof TIME_RANGE_OPTIONS)[keyof typeof TIME_RANGE_OPTIONS];

export const TIME_RANGE_DAYS: Record<TimeRange, number> = {
  "5D": 5,
  "1W": 7,
  "1M": 30,
};

export const DEFAULT_TIME_RANGE: TimeRange = "5D";

export const getDateFromForTimeRange = (timeRange: TimeRange): string => {
  const days = TIME_RANGE_DAYS[timeRange];
  const date = new Date();
  date.setDate(date.getDate() - days);
  return date.toISOString().split("T")[0];
};
