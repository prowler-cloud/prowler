"use client";

import {
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
} from "recharts";

import { CHART_COLORS } from "./shared/constants";
interface RadialChartProps {
  percentage: number;
  label?: string;
  color?: string;
  backgroundColor?: string;
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  startAngle?: number;
  endAngle?: number;
}

export function RadialChart({
  percentage,
  label = "Score",
  color = "var(--chart-success-color)",
  backgroundColor = CHART_COLORS.tooltipBackground,
  height = 250,
  innerRadius = 60,
  outerRadius = 100,
  startAngle = 90,
  endAngle = -270,
}: RadialChartProps) {
  const data = [
    {
      name: label,
      value: percentage,
      fill: color,
    },
  ];

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadialBarChart
        cx="50%"
        cy="50%"
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        barSize={20}
        data={data}
        startAngle={startAngle}
        endAngle={endAngle}
      >
        <PolarAngleAxis
          type="number"
          domain={[0, 100]}
          angleAxisId={0}
          tick={false}
        />
        <RadialBar
          background={{ fill: backgroundColor }}
          dataKey="value"
          cornerRadius={10}
          fill={color}
        />
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="text-4xl font-bold"
          style={{
            fill: "var(--chart-text-primary)",
          }}
        >
          {percentage}%
        </text>
      </RadialBarChart>
    </ResponsiveContainer>
  );
}
