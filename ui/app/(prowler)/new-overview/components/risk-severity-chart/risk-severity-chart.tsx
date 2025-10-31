"use client";

import { HorizontalBarChart } from "@/components/graphs/horizontal-bar-chart";
import { BarDataPoint } from "@/components/graphs/types";
import { calculatePercentage } from "@/lib/utils";

interface RiskSeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export const RiskSeverityChart = ({
  critical,
  high,
  medium,
  low,
  informational,
}: RiskSeverityChartProps) => {
  // Calculate total findings
  const totalFindings = critical + high + medium + low + informational;

  // Transform data to BarDataPoint format
  const chartData: BarDataPoint[] = [
    {
      name: "Critical",
      value: critical,
      percentage: calculatePercentage(critical, totalFindings),
    },
    {
      name: "High",
      value: high,
      percentage: calculatePercentage(high, totalFindings),
    },
    {
      name: "Medium",
      value: medium,
      percentage: calculatePercentage(medium, totalFindings),
    },
    {
      name: "Low",
      value: low,
      percentage: calculatePercentage(low, totalFindings),
    },
    {
      name: "Info",
      value: informational,
      percentage: calculatePercentage(informational, totalFindings),
    },
  ];

  return <HorizontalBarChart data={chartData} />;
};
