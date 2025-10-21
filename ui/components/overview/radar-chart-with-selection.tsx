"use client";

import { useState } from "react";

import { RadarChart } from "@/components/graphs";
import type { RadarDataPoint } from "@/components/graphs/types";

interface RadarChartWithSelectionProps {
  data?: RadarDataPoint[];
  height?: number;
}

const sampleRadarData: RadarDataPoint[] = [
  { category: "IAM", value: 85, change: 5 },
  { category: "Storage", value: 72, change: -2 },
  { category: "Network", value: 88, change: 8 },
  { category: "Compute", value: 76, change: 3 },
  { category: "Database", value: 82, change: -1 },
  { category: "Encryption", value: 91, change: 6 },
];

export function RadarChartWithSelection({
  data = sampleRadarData,
  height = 400,
}: RadarChartWithSelectionProps) {
  const [selectedPoint, setSelectedPoint] = useState<RadarDataPoint | null>(
    null,
  );

  return (
    <RadarChart
      data={data}
      height={height}
      selectedPoint={selectedPoint}
      onSelectPoint={setSelectedPoint}
    />
  );
}
