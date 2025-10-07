"use client";

import { useState } from "react";
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

import { DonutDataPoint } from "./models/chart-types";
import { CHART_COLORS } from "./shared/chart-constants";
import { ChartTooltip } from "./shared/ChartTooltip";

interface DonutChartProps {
  data: DonutDataPoint[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  showLegend?: boolean;
  centerLabel?: {
    value: string | number;
    label: string;
  };
}

const CustomLabel = ({
  cx,
  cy,
  value,
  label,
}: {
  cx: number;
  cy: number;
  value: string | number;
  label: string;
}) => {
  return (
    <>
      <text
        x={cx}
        y={cy - 10}
        textAnchor="middle"
        dominantBaseline="middle"
        style={{ fill: CHART_COLORS.textPrimary }}
        className="text-3xl font-bold"
      >
        {value}
      </text>
      <text
        x={cx}
        y={cy + 15}
        textAnchor="middle"
        dominantBaseline="middle"
        style={{ fill: CHART_COLORS.textSecondary }}
        className="text-sm"
      >
        {label}
      </text>
    </>
  );
};

export function DonutChart({
  data,
  height = 300,
  innerRadius = 60,
  outerRadius = 100,
  showLegend = true,
  centerLabel,
}: DonutChartProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          paddingAngle={2}
          dataKey="value"
          label={false}
          onMouseEnter={(_, index) => setHoveredIndex(index)}
          onMouseLeave={() => setHoveredIndex(null)}
        >
          {data.map((entry, index) => {
            const opacity =
              hoveredIndex === null ? 1 : hoveredIndex === index ? 1 : 0.5;
            return (
              <Cell
                key={`cell-${index}`}
                fill={entry.color}
                opacity={opacity}
                style={{ transition: "opacity 0.2s" }}
              />
            );
          })}
        </Pie>
        {centerLabel && (
          <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle">
            <CustomLabel
              cx={0}
              cy={0}
              value={centerLabel.value}
              label={centerLabel.label}
            />
          </text>
        )}
        <Tooltip content={<ChartTooltip colorIndicatorShape="circle" />} />
        {showLegend && (
          <Legend
            verticalAlign="bottom"
            height={36}
            iconType="circle"
            formatter={(value, entry: any) => (
              <span
                className="text-sm"
                style={{ color: CHART_COLORS.textPrimary }}
              >
                {value} ({entry.payload.percentage}%)
              </span>
            )}
          />
        )}
      </PieChart>
    </ResponsiveContainer>
  );
}
