"use client";

import {
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { AlertPill } from "./shared/alert-pill";
import { ChartLegend } from "./shared/chart-legend";
import { CHART_COLORS } from "./shared/constants";
import { getSeverityColorByRiskScore } from "./shared/utils";
import type { ScatterDataPoint } from "./types";

interface ScatterPlotProps {
  data: ScatterDataPoint[];
  xLabel?: string;
  yLabel?: string;
  height?: number;
  onSelectPoint?: (point: ScatterDataPoint | null) => void;
  selectedPoint?: ScatterDataPoint | null;
}

const PROVIDER_COLORS = {
  AWS: "var(--chart-provider-aws)",
  Azure: "var(--chart-provider-azure)",
  Google: "var(--chart-provider-google)",
};

const CustomTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const severityColor = getSeverityColorByRiskScore(data.x);

    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: CHART_COLORS.tooltipBorder,
          backgroundColor: CHART_COLORS.tooltipBackground,
        }}
      >
        <p
          className="text-sm font-semibold"
          style={{ color: CHART_COLORS.textPrimary }}
        >
          {data.name}
        </p>
        <p
          className="mt-1 text-xs"
          style={{ color: CHART_COLORS.textSecondary }}
        >
          <span style={{ color: severityColor }}>{data.x}</span> Risk Score
        </p>
        <div className="mt-2">
          <AlertPill value={data.y} />
        </div>
      </div>
    );
  }
  return null;
};

const CustomScatterDot = ({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
}: any) => {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const fill = isSelected
    ? "#86DA26"
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      CHART_COLORS.defaultColor;

  return (
    <circle
      cx={cx}
      cy={cy}
      r={size / 2}
      fill={fill}
      stroke={isSelected ? "#86DA26" : "transparent"}
      strokeWidth={2}
      className={isSelected ? "drop-shadow-[0_0_8px_#86da26]" : ""}
      style={{ cursor: "pointer" }}
      onClick={() => onSelectPoint?.(payload)}
    />
  );
};

const CustomLegend = ({ payload }: any) => {
  const items = payload.map((entry: any) => ({
    label: entry.value,
    color: entry.color,
  }));

  return <ChartLegend items={items} />;
};

export function ScatterPlot({
  data,
  xLabel = "Risk Score",
  yLabel = "Failed Findings",
  height = 400,
  onSelectPoint,
  selectedPoint,
}: ScatterPlotProps) {
  const handlePointClick = (point: ScatterDataPoint) => {
    if (onSelectPoint) {
      if (selectedPoint?.name === point.name) {
        onSelectPoint(null);
      } else {
        onSelectPoint(point);
      }
    }
  };

  const dataByProvider = data.reduce(
    (acc, point) => {
      const provider = point.provider;
      if (!acc[provider]) {
        acc[provider] = [];
      }
      acc[provider].push(point);
      return acc;
    },
    {} as Record<string, ScatterDataPoint[]>,
  );

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.gridLine} />
        <XAxis
          type="number"
          dataKey="x"
          name={xLabel}
          label={{
            value: xLabel,
            position: "insideBottom",
            offset: -10,
            fill: CHART_COLORS.textSecondary,
          }}
          tick={{ fill: CHART_COLORS.textSecondary }}
          domain={[0, 10]}
        />
        <YAxis
          type="number"
          dataKey="y"
          name={yLabel}
          label={{
            value: yLabel,
            angle: -90,
            position: "insideLeft",
            fill: CHART_COLORS.textSecondary,
          }}
          tick={{ fill: CHART_COLORS.textSecondary }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend content={<CustomLegend />} />
        {Object.entries(dataByProvider).map(([provider, points]) => (
          <Scatter
            key={provider}
            name={provider}
            data={points}
            fill={
              PROVIDER_COLORS[provider as keyof typeof PROVIDER_COLORS] ||
              CHART_COLORS.defaultColor
            }
            shape={(props: any) => (
              <CustomScatterDot
                {...props}
                selectedPoint={selectedPoint}
                onSelectPoint={handlePointClick}
              />
            )}
          />
        ))}
      </ScatterChart>
    </ResponsiveContainer>
  );
}
