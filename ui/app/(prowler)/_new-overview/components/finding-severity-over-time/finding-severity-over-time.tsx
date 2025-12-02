"use client";

import { useState } from "react";

import { getSeverityTrendsByTimeRange } from "@/actions/overview/severity-trends";
import { SeverityDataPoint } from "@/actions/overview/severity-trends.adapter";
import { LineChart } from "@/components/graphs/line-chart";
import { LineConfig, LineDataPoint } from "@/components/graphs/types";
import { Skeleton } from "@/components/shadcn";
import { MUTED_COLOR, SEVERITY_LINE_CONFIGS } from "@/types/severities";

import { type TimeRange, TimeRangeSelector } from "./time-range-selector";

interface FindingSeverityOverTimeProps {
  data: SeverityDataPoint[];
}

export const FindingSeverityOverTime = ({
  data: initialData,
}: FindingSeverityOverTimeProps) => {
  const [timeRange, setTimeRange] = useState<TimeRange>("5D");
  const [data, setData] = useState<SeverityDataPoint[]>(initialData);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleTimeRangeChange = async (newRange: TimeRange) => {
    setTimeRange(newRange);
    setIsLoading(true);
    setError(null);

    try {
      const response = await getSeverityTrendsByTimeRange({
        timeRange: newRange,
      });

      if (response?.data) {
        setData(response.data);
      }
    } catch (err) {
      console.error("Error fetching severity trends:", err);
      setError("Failed to load severity trends. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  // Transform API data into LineDataPoint format
  const chartData: LineDataPoint[] = data.map((item) => {
    const date = new Date(item.date);
    const formattedDate = date.toLocaleDateString("en-US", {
      month: "2-digit",
      day: "2-digit",
    });

    return {
      date: formattedDate,
      informational: item.informational,
      low: item.low,
      medium: item.medium,
      high: item.high,
      critical: item.critical,
      ...(item.muted && { muted: item.muted }),
    };
  });

  // Build line configurations from shared severity configs
  const lines: LineConfig[] = [...SEVERITY_LINE_CONFIGS];

  // Only add muted line if data contains it
  if (data.some((item) => item.muted !== undefined)) {
    lines.push({
      dataKey: "muted",
      color: MUTED_COLOR,
      label: "Muted",
    });
  }

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
          <LineChart data={chartData} lines={lines} height={400} />
        </div>
      )}
    </>
  );
};

export function FindingSeverityOverTimeSkeleton() {
  return (
    <div role="status" aria-label="Loading severity trends">
      <div className="mb-8 w-fit">
        <div className="flex gap-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <Skeleton key={index} className="h-10 w-12 rounded-full" />
          ))}
        </div>
      </div>
      <Skeleton className="h-[400px] w-full rounded-lg" />
    </div>
  );
}
