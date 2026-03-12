"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { getSeverityTrendsByTimeRange } from "@/actions/overview/severity-trends";
import { LineChart } from "@/components/graphs/line-chart";
import { LineConfig, LineDataPoint } from "@/components/graphs/types";
import {
  SEVERITY_LEVELS,
  SEVERITY_LINE_CONFIGS,
  SeverityLevel,
} from "@/types/severities";

import { DEFAULT_TIME_RANGE } from "../_constants/time-range.constants";
import { type TimeRange, TimeRangeSelector } from "./time-range-selector";

interface FindingSeverityOverTimeProps {
  data: LineDataPoint[];
}

export const FindingSeverityOverTime = ({
  data: initialData,
}: FindingSeverityOverTimeProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [timeRange, setTimeRange] = useState<TimeRange>(DEFAULT_TIME_RANGE);
  const [data, setData] = useState<LineDataPoint[]>(initialData);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync data when SSR re-delivers filtered results (e.g. provider/account filter change).
  // Uses the "set state during render" pattern so the update is synchronous — no flash of stale data.
  const [prevInitialData, setPrevInitialData] = useState(initialData);
  if (initialData !== prevInitialData) {
    setPrevInitialData(initialData);
    setData(initialData);
    setError(null);
    setTimeRange(DEFAULT_TIME_RANGE);
  }

  const getActiveProviderFilters = (): Record<string, string> => {
    const filters: Record<string, string> = {};
    const providerType = searchParams.get("filter[provider_type__in]");
    const providerId = searchParams.get("filter[provider_id__in]");
    if (providerType) filters["filter[provider_type__in]"] = providerType;
    if (providerId) filters["filter[provider_id__in]"] = providerId;
    return filters;
  };

  const handlePointClick = ({
    point,
    dataKey,
  }: {
    point: LineDataPoint;
    dataKey?: string;
  }) => {
    const params = new URLSearchParams();

    // Always filter by FAIL status since this chart shows failed findings
    params.set("filter[status__in]", "FAIL");

    // Exclude muted findings
    params.set("filter[muted]", "false");

    // Add scan_ids filter
    if (
      point.scan_ids &&
      Array.isArray(point.scan_ids) &&
      point.scan_ids.length > 0
    ) {
      params.set("filter[scan__in]", point.scan_ids.join(","));
    }

    // Add severity filter if clicked on a specific severity line
    if (dataKey && SEVERITY_LEVELS.includes(dataKey as SeverityLevel)) {
      params.set("filter[severity__in]", dataKey);
    }

    // Preserve provider filters from overview
    const providerFilters = getActiveProviderFilters();
    for (const [key, value] of Object.entries(providerFilters)) {
      params.set(key, value);
    }

    router.push(`/findings?${params.toString()}`);
  };

  const handleTimeRangeChange = async (newRange: TimeRange) => {
    setTimeRange(newRange);
    setIsLoading(true);
    setError(null);

    try {
      const result = await getSeverityTrendsByTimeRange({
        timeRange: newRange,
        filters: getActiveProviderFilters(),
      });

      if (result.status === "success") {
        setData(result.data.data);
      } else if (result.status === "empty") {
        setData([]);
        setError("No severity trends data available for this time range");
      } else {
        setError("Failed to load severity trends. Please try again.");
      }
    } catch (err) {
      console.error("Error fetching severity trends:", err);
      setError("Failed to load severity trends. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  // Build line configurations from shared severity configs
  const lines: LineConfig[] = [...SEVERITY_LINE_CONFIGS];

  // Calculate x-axis interval based on data length to show all labels without overlap
  const getXAxisInterval = (): number => {
    const dataLength = data.length;
    if (dataLength <= 7) return 0; // Show all labels for 5D and 1W
    return 0; // Show all labels for 1M too
  };

  return (
    <>
      <div className="mb-8 w-fit">
        <TimeRangeSelector
          value={timeRange}
          onChange={handleTimeRangeChange}
          isLoading={isLoading}
        />
      </div>
      {error ? (
        <div
          role="alert"
          className="flex h-[400px] w-full items-center justify-center rounded-lg border border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950"
        >
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </div>
      ) : (
        <div className="mb-4 w-full">
          <LineChart
            data={data}
            lines={lines}
            height={400}
            xAxisInterval={getXAxisInterval()}
            onPointClick={handlePointClick}
          />
        </div>
      )}
    </>
  );
};
