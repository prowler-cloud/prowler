"use client";

import { useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart as RechartsLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { LineConfig, LineDataPoint } from "./models/chart-types";
import { CHART_COLORS } from "./shared/chart-constants";
import { MultiSeriesChartTooltip } from "./shared/ChartTooltip";

interface LineChartProps {
  data: LineDataPoint[];
  lines: LineConfig[];
  xLabel?: string;
  yLabel?: string;
  height?: number;
}

export function LineChart({
  data,
  lines,
  xLabel,
  yLabel,
  height = 400,
}: LineChartProps) {
  const [hoveredLine, setHoveredLine] = useState<string | null>(null);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsLine
        data={data}
        margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke={CHART_COLORS.gridLine} />
        <XAxis
          dataKey="date"
          label={
            xLabel
              ? {
                  value: xLabel,
                  position: "insideBottom",
                  offset: -10,
                  fill: CHART_COLORS.textSecondary,
                }
              : undefined
          }
          tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
        />
        <YAxis
          label={
            yLabel
              ? {
                  value: yLabel,
                  angle: -90,
                  position: "insideLeft",
                  fill: CHART_COLORS.textSecondary,
                }
              : undefined
          }
          tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
        />
        <Tooltip content={<MultiSeriesChartTooltip />} />
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
        {lines.map((line) => {
          const isHovered = hoveredLine === line.dataKey;
          const isFaded = hoveredLine !== null && !isHovered;
          return (
            <Line
              key={line.dataKey}
              type="monotone"
              dataKey={line.dataKey}
              stroke={line.color}
              strokeWidth={2}
              strokeOpacity={isFaded ? 0.5 : 1}
              name={line.label}
              dot={{ fill: line.color, r: 4, opacity: isFaded ? 0.5 : 1 }}
              activeDot={{ r: 6 }}
              onMouseEnter={() => setHoveredLine(line.dataKey)}
              onMouseLeave={() => setHoveredLine(null)}
              style={{ transition: "stroke-opacity 0.2s" }}
            />
          );
        })}
      </RechartsLine>
    </ResponsiveContainer>
  );
}
