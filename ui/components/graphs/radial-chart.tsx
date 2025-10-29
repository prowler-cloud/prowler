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
  hasDots?: boolean;
}

export function RadialChart({
  percentage,
  color = "var(--chart-success-color)",
  backgroundColor = CHART_COLORS.tooltipBackground,
  height = 250,
  innerRadius = 60,
  outerRadius = 100,
  startAngle = 90,
  endAngle = -270,
  hasDots = false,
}: RadialChartProps) {
  // Calculate the real barSize based on the difference
  const barSize = outerRadius - innerRadius;
  const data = [
    {
      value: percentage,
    },
  ];
  const middleRadius = innerRadius;
  const viewBoxWidth = height;
  const viewBoxHeight = height;
  const centerX = viewBoxWidth / 2;
  const centerY = viewBoxHeight / 2;
  const arcAngle = Math.abs(startAngle - endAngle);
  const dotSpacing = 20; // 4px dot + 8px space
  const arcCircumference = (arcAngle / 360) * (2 * Math.PI * middleRadius);
  const numberOfDots = Math.floor(arcCircumference / dotSpacing);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadialBarChart
        cx="50%"
        cy="50%"
        innerRadius={innerRadius}
        outerRadius={outerRadius}
        barSize={barSize}
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
          fill={color}
          cornerRadius={10}
          isAnimationActive={false}
        />

        {hasDots &&
          Array.from({ length: numberOfDots })
            .slice(0, -1)
            .map((_, i) => {
              // Calculate the angle for this point
              const angleProgress = i / (numberOfDots - 1 || 1);
              const currentAngle =
                startAngle - angleProgress * (startAngle - endAngle);

              // Show dots only in the background part (after the percentage value)
              const valueAngleEnd =
                startAngle - (percentage / 100) * (startAngle - endAngle);
              if (currentAngle > valueAngleEnd) {
                return null; // Don't show dots in the part with value
              }

              const currentAngleRad = (currentAngle * Math.PI) / 180;

              // Calculate absolute position in the viewBox
              const x = centerX + middleRadius * Math.cos(currentAngleRad) + 22;
              const y = centerY - middleRadius * Math.sin(currentAngleRad);

              return (
                <circle
                  key={i}
                  cx={x}
                  cy={y}
                  r={2}
                  fill="rgba(255, 255, 255, 0.3)"
                />
              );
            })}

        <text
          x="50%"
          y="40%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="text-2xl font-bold"
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
