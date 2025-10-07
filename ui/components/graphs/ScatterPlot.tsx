"use client";

import { useState } from "react";
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

import { AlertPill } from "./shared/AlertPill";
import { CHART_COLORS, SEVERITY_COLORS } from "./shared/chart-constants";

interface ScatterDataPoint {
  x: number;
  y: number;
  provider: string;
  name: string;
  size?: number;
}

interface ScatterPlotProps {
  data: ScatterDataPoint[];
  xLabel?: string;
  yLabel?: string;
  height?: number;
  onSelectPoint?: (point: ScatterDataPoint | null) => void;
  selectedPoint?: ScatterDataPoint | null;
}

const PROVIDER_COLORS = {
  AWS: "var(--color-orange)",
  Azure: "var(--color-cyan)",
  Google: "var(--color-red)",
};

const getSeverityColorByRiskScore = (riskScore: number): string => {
  if (riskScore >= 7) return SEVERITY_COLORS.Critical;
  if (riskScore >= 5) return SEVERITY_COLORS.High;
  if (riskScore >= 3) return SEVERITY_COLORS.Medium;
  if (riskScore >= 1) return SEVERITY_COLORS.Low;
  return SEVERITY_COLORS.Info;
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
        <p className="mt-1 text-xs" style={{ color: CHART_COLORS.textSecondary }}>
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
    ? "var(--color-success)"
    : PROVIDER_COLORS[payload.provider as keyof typeof PROVIDER_COLORS] ||
      "#6B7280";

  return (
    <circle
      cx={cx}
      cy={cy}
      r={size / 2}
      fill={fill}
      stroke={isSelected ? "var(--color-success)" : "transparent"}
      strokeWidth={2}
      style={{ cursor: "pointer" }}
      onClick={() => onSelectPoint?.(payload)}
    />
  );
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
        <Legend
          wrapperStyle={{ paddingTop: "20px" }}
          iconType="circle"
          formatter={(value) => (
            <span
              className="text-sm"
              style={{ color: CHART_COLORS.textPrimary }}
            >
              {value}
            </span>
          )}
        />
        {Object.entries(dataByProvider).map(([provider, points]) => (
          <Scatter
            key={provider}
            name={provider}
            data={points}
            fill={
              PROVIDER_COLORS[provider as keyof typeof PROVIDER_COLORS] ||
              "#6B7280"
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
