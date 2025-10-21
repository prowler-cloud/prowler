"use client";

import { ScatterPlot } from "@/components/graphs";

interface DataPoint {
  x: number;
  y: number;
  provider: string;
  name: string;
  size: number;
}

interface ScatterPlotWithSelectionProps {
  data: DataPoint[];
  height?: number;
  xLabel?: string;
  yLabel?: string;
}

export function ScatterPlotWithSelection({
  data,
  height = 400,
  xLabel = "Risk Score",
  yLabel = "Compliance %",
}: ScatterPlotWithSelectionProps) {
  return (
    <ScatterPlot
      data={data}
      height={height}
      xLabel={xLabel}
      yLabel={yLabel}
    />
  );
}
