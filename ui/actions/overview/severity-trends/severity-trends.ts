"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import { adaptSeverityTrendsResponse } from "./severity-trends.adapter";
import {
  AdaptedSeverityTrendsResponse,
  FindingsSeverityOverTimeResponse,
} from "../types";

// TODO: Remove mock data before committing
const generateMockData = (days: number): FindingsSeverityOverTimeResponse => {
  const data = [];
  const endDate = new Date();

  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(endDate.getTime() - i * 24 * 60 * 60 * 1000);
    const dateStr = date.toISOString().split("T")[0];

    data.push({
      id: dateStr,
      type: "findings-severity-over-time" as const,
      attributes: {
        critical: Math.floor(Math.random() * 30) + 5,
        high: Math.floor(Math.random() * 50) + 30,
        medium: Math.floor(Math.random() * 60) + 60,
        low: Math.floor(Math.random() * 80) + 100,
        informational: Math.floor(Math.random() * 100) + 150,
        muted: Math.floor(Math.random() * 20) + 10,
        scan_ids: [`scan-${i}-1`, `scan-${i}-2`],
      },
    });
  }

  return { data, meta: { version: "mock" } };
};

// TODO: Set to false before committing
const USE_MOCK = true;

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

export type SeverityTrendsResult =
  | { status: "success"; data: AdaptedSeverityTrendsResponse }
  | { status: "empty" }
  | { status: "error" };

const getFindingsSeverityTrends = async ({
  filters = {},
}: {
  filters?: Record<string, string | string[] | undefined>;
} = {}): Promise<SeverityTrendsResult> => {
  // TODO: Remove mock usage before committing
  if (USE_MOCK) {
    // Calculate days from date_from filter
    const dateFrom = filters.date_from as string | undefined;
    let days = 5;
    if (dateFrom) {
      const startDate = new Date(dateFrom);
      const endDate = new Date();
      days = Math.ceil(
        (endDate.getTime() - startDate.getTime()) / (24 * 60 * 60 * 1000),
      );
    }
    return {
      status: "success",
      data: adaptSeverityTrendsResponse(generateMockData(days)),
    };
  }

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
  const days = TIME_RANGE_DAYS[timeRange];

  if (!days) {
    console.error("Invalid time range provided");
    return { status: "error" };
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
