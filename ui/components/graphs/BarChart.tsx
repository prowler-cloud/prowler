"use client";

import {
  Bar,
  BarChart as RechartsBar,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { BarDataPoint, LayoutOption } from "./models/chart-types";
import { CHART_COLORS, LAYOUT_OPTIONS } from "./shared/constants";
import { ChartTooltip } from "./shared/ChartTooltip";
import { getSeverityColorByName } from "./shared/utils";

interface BarChartProps {
  data: BarDataPoint[];
  layout?: LayoutOption;
  xLabel?: string;
  yLabel?: string;
  height?: number;
  showValues?: boolean;
}

const CustomLabel = ({ x, y, width, height, value, data }: any) => {
  const percentage = data.percentage;
  return (
    <text
      x={x + width + 10}
      y={y + height / 2}
      fill={CHART_COLORS.textSecondary}
      fontSize={12}
      textAnchor="start"
      dominantBaseline="middle"
    >
      {percentage !== undefined
        ? `${percentage}% • ${value.toLocaleString()}`
        : value.toLocaleString()}
    </text>
  );
};

export function BarChart({
  data,
  layout = LAYOUT_OPTIONS.horizontal,
  xLabel,
  yLabel,
  height = 400,
  showValues = true,
}: BarChartProps) {
  const isHorizontal = layout === LAYOUT_OPTIONS.horizontal;

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RechartsBar
        data={data}
        layout={layout}
        margin={{ top: 20, right: showValues ? 100 : 30, left: 20, bottom: 20 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={CHART_COLORS.gridLine}
          horizontal={isHorizontal}
          vertical={!isHorizontal}
        />
        {isHorizontal ? (
          <>
            <XAxis
              type="number"
              tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
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
            />
            <YAxis
              dataKey="name"
              type="category"
              width={100}
              tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
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
            />
          </>
        ) : (
          <>
            <XAxis
              dataKey="name"
              tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
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
            />
            <YAxis
              type="number"
              tick={{ fill: CHART_COLORS.textSecondary, fontSize: 12 }}
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
            />
          </>
        )}
        <Tooltip content={<ChartTooltip />} />
        <Bar
          dataKey="value"
          radius={4}
          label={
            showValues && isHorizontal
              ? (props: any) => (
                  <CustomLabel {...props} data={data[props.index]} />
                )
              : false
          }
        >
          {data.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={
                entry.color || getSeverityColorByName(entry.name) || "#6B7280"
              }
              opacity={1}
              className="transition-opacity hover:opacity-80"
            />
          ))}
        </Bar>
      </RechartsBar>
    </ResponsiveContainer>
  );
}
