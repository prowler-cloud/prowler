"use client";

import { RadarChart } from "@/components/graphs";

interface RadarChartWithSelectionProps {
  percentage?: number;
  label?: string;
  color?: string;
  height?: number;
}

export function RadarChartWithSelection({
  percentage = 78,
  label = "Overall Compliance",
  color = "var(--chart-success-color)",
  height = 350,
}: RadarChartWithSelectionProps) {
  return (
    <RadarChart
      percentage={percentage}
      label={label}
      color={color}
      height={height}
    />
  );
}
