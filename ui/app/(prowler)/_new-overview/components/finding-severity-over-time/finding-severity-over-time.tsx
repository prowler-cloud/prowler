"use client";

import { useState } from "react";

import { getSeverityTrendsByTimeRange } from "@/actions/overview/severity-trends";
import { LineChart } from "@/components/graphs/line-chart";
import { LineConfig, LineDataPoint } from "@/components/graphs/types";
import { Skeleton } from "@/components/shadcn";
import { MUTED_COLOR, SEVERITY_LINE_CONFIGS } from "@/types/severities";

import { type TimeRange, TimeRangeSelector } from "./time-range-selector";

interface FindingSeverityOverTimeProps {
  data: LineDataPoint[];
}

export const FindingSeverityOverTime = ({
  data: initialData,
}: FindingSeverityOverTimeProps) => {
  const [timeRange, setTimeRange] = useState<TimeRange>("5D");
  const [data, setData] = useState<LineDataPoint[]>(initialData);
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
          />
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
