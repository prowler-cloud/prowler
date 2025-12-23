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
  AWS: "var(--color-bg-data-aws)",
  Azure: "var(--color-bg-data-azure)",
  Google: "var(--color-bg-data-gcp)",
  Default: "var(--color-text-neutral-tertiary)",
};

interface ScatterTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ScatterDataPoint }>;
}

const CustomTooltip = ({ active, payload }: ScatterTooltipProps) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    const severityColor = getSeverityColorByRiskScore(data.x);

    return (
      <div
        className="rounded-lg border p-3 shadow-lg"
        style={{
          borderColor: "var(--color-border-neutral-tertiary)",
          backgroundColor: "var(--color-bg-neutral-secondary)",
        }}
      >
        <p
          className="text-sm font-semibold"
          style={{ color: "var(--color-text-neutral-primary)" }}
        >
          {data.name}
        </p>
        <p
          className="mt-1 text-xs"
          style={{ color: "var(--color-text-neutral-secondary)" }}
        >
          Risk Score: <span style={{ color: severityColor }}>{data.x}</span>
        </p>
        <div className="mt-2">
          <AlertPill value={data.y} label="Failed Findings" />
        </div>
      </div>
    );
  }
  return null;
};

interface ScatterDotProps {
  cx: number;
  cy: number;
  payload: ScatterDataPoint;
  selectedPoint?: ScatterDataPoint | null;
  onSelectPoint?: (point: ScatterDataPoint) => void;
}

const SELECTED_COLOR = "var(--bg-button-primary)";

const CustomScatterDot = ({
  cx,
  cy,
  payload,
  selectedPoint,
  onSelectPoint,
}: ScatterDotProps) => {
  const isSelected = selectedPoint?.name === payload.name;
  const size = isSelected ? 18 : 8;
  const fill = isSelected
    ? SELECTED_COLOR
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      "var(--color-text-neutral-tertiary)";

  return (
    <circle
      cx={cx}
      cy={cy}
      r={size / 2}
      fill={fill}
      stroke={isSelected ? SELECTED_COLOR : "transparent"}
      strokeWidth={2}
      className={isSelected ? "selected-dot-glow" : ""}
      style={{ cursor: "pointer" }}
      onClick={() => onSelectPoint?.(payload)}
    />
  );
};

interface LegendPayloadItem {
  value: string;
  color: string;
}

interface LegendProps {
  payload?: LegendPayloadItem[];
}

const CustomLegend = ({ payload }: LegendProps) => {
  const items = (payload || []).map((entry) => ({
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
    <div
      className="relative h-full w-full"
      style={{
        background:
          "linear-gradient(to bottom, transparent 0%, rgba(125, 26, 26, 0.6) 100%)",
      }}
    >
      <ResponsiveContainer width="100%" height={height}>
        <ScatterChart margin={{ top: 20, right: 30, bottom: 60, left: 60 }}>
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="var(--color-border-neutral-tertiary)"
          />
          <XAxis
            type="number"
            dataKey="x"
            name={xLabel}
            label={{
              value: xLabel,
              position: "bottom",
              offset: 10,
              fill: "var(--color-text-neutral-secondary)",
            }}
            tick={{ fill: "var(--color-text-neutral-secondary)" }}
          />
          <YAxis
            type="number"
            dataKey="y"
            name={yLabel}
            label={{
              value: yLabel,
              angle: -90,
              position: "left",
              offset: 10,
              fill: "var(--color-text-neutral-secondary)",
            }}
            tick={{ fill: "var(--color-text-neutral-secondary)" }}
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
                PROVIDER_COLORS.Default
              }
              shape={(props: unknown) => {
                const dotProps = props as ScatterDotProps;
                return (
                  <CustomScatterDot
                    {...dotProps}
                    selectedPoint={selectedPoint}
                    onSelectPoint={handlePointClick}
                  />
                );
              }}
            />
          ))}
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}
