"use client";

import { useState } from "react";

import { getSeverityTrendsByTimeRange } from "@/actions/overview/severity-trends";
import { LineChart } from "@/components/graphs/line-chart";
import { SEVERITY_COLORS } from "@/components/graphs/shared/constants";
import { LineConfig, LineDataPoint } from "@/components/graphs/types";

import { type TimeRange, TimeRangeSelector } from "./time-range-selector";

interface SeverityDataPoint {
  type: string;
  id: string;
  date: string;
  informational: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
  muted?: number;
}

interface FindingSeverityOverTimeProps {
  data: SeverityDataPoint[];
}

export const FindingSeverityOverTime = ({
  data: initialData,
}: FindingSeverityOverTimeProps) => {
  const [timeRange, setTimeRange] = useState<TimeRange>("5D");
  const [data, setData] = useState<SeverityDataPoint[]>(initialData);
  const [isLoading, setIsLoading] = useState(false);

  const handleTimeRangeChange = async (newRange: TimeRange) => {
    setTimeRange(newRange);
    setIsLoading(true);

    try {
      const response = await getSeverityTrendsByTimeRange({
        timeRange: newRange,
      });

      if (response?.data) {
        setData(response.data);
      }
    } catch (error) {
      console.error("Error fetching severity trends:", error);
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

  // Define line configurations for each severity level
  const lines: LineConfig[] = [
    {
      dataKey: "informational",
      color: SEVERITY_COLORS.Informational,
      label: "Informational",
    },
    {
      dataKey: "low",
      color: SEVERITY_COLORS.Low,
      label: "Low",
    },
    {
      dataKey: "medium",
      color: SEVERITY_COLORS.Medium,
      label: "Medium",
    },
    {
      dataKey: "high",
      color: SEVERITY_COLORS.High,
      label: "High",
    },
    {
      dataKey: "critical",
      color: SEVERITY_COLORS.Critical,
      label: "Critical",
    },
  ];

  // Only add muted line if data contains it
  if (data.some((item) => item.muted !== undefined)) {
    lines.push({
      dataKey: "muted",
      color: "hsl(var(--chart-muted))",
      label: "Muted",
    });
  }

  return (
    <>
      <div className="mb-4">
        <TimeRangeSelector
          value={timeRange}
          onChange={handleTimeRangeChange}
          isLoading={isLoading}
        />
      </div>

      <div className="w-full">
        <LineChart data={chartData} lines={lines} height={400} />
      </div>
    </>
  );
};
